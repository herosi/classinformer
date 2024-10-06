
// WaitBoxEx: Custom IDA Pro wait box
// By Sirmabus
// http://www.macromonkey.com
// License: Qt LGPL
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <exception>

#include <QtWidgets/QMainWindow>

#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
// IDA SDK Qt libs
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

#include "WaitBoxEx.h"
#include "WinTaskProgress.h"
#include "MyQProgressDialog.h"

// Alternate "Material design" inspired style
#ifdef MATERIAL_DESIGN_STYLE
#pragma message("* Material design style build *")
#endif

static const int  DAILOG_WIDTH = 250, DAILOG_HEIGHT = 105;
static const int  BUTTON_WIDTH = 90, BUTTON_HEIGHT = 25;
static const char FONT[] = { "Tahoma" };
static const UINT SHOW_DELAY = (2 * 1000);
static const UINT TARGET_UPDATE_MS = 100;
#ifndef MATERIAL_DESIGN_STYLE
static const LPCSTR CANCEL = "Cancel";
#else
static const LPCSTR CANCEL = "CANCEL";
#endif

static BOOL showState = FALSE, isUpdateReady = TRUE;
static MyQProgressDialog *prgDlg = NULL;

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception in WaitBoxEx method: %s()! ***\n", __FUNCTION__); }

// QT_NO_UNICODE_LITERAL must be defined (best in preprocessor setting)
// So Qt doesn't a static string pool that will cause IDA to crash on unload
#ifndef QT_NO_UNICODE_LITERAL
# error QT_NO_UNICODE_LITERAL must be defined to avoid Qt string crashes
#endif

static HWND WINAPI getIdaHwnd()
{
	static HWND mainHwnd = nullptr;
	if (!mainHwnd)
	{
		foreach(QWidget *w, QApplication::topLevelWidgets())
		{
			if (QMainWindow *mw = qobject_cast<QMainWindow*>(w))
			{
				mainHwnd = HWND(mw->winId());
				break;
			}
		}
	}
	return mainHwnd;
}

static void CALLBACK timerTick(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{	
    isUpdateReady = TRUE;	
}

// Consume left mouse clicks on title bar to make it undraggable
static LRESULT CALLBACK mouseHook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
        if ((wParam == WM_NCLBUTTONDOWN) && (((LPMOUSEHOOKSTRUCT) lParam)->wHitTestCode == HTCAPTION))
            return(TRUE);
    return(CallNextHookEx(NULL, nCode, wParam, lParam));
}

// Make the IDA window minimize when the dialog does
// Because of windowslog+M eventFilter() won't do
static LRESULT CALLBACK msgHook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
        LPCWPSTRUCT ms = (LPCWPSTRUCT)lParam;
        if (ms->message == WM_SIZE)
        {
            if (prgDlg && (ms->hwnd == (HWND) prgDlg->winId()))
            {
                if (ms->wParam == SIZE_MINIMIZED)
                    ::ShowWindow(getIdaHwnd(), SW_MINIMIZE);
                else
                if (ms->wParam == SIZE_RESTORED)
                    ::ShowWindow(getIdaHwnd(), SW_SHOW);
            }
        }
    }
    return(CallNextHookEx(NULL, nCode, wParam, lParam));
}


// Subclass QProgressDialog()
MyQProgressDialog::MyQProgressDialog(LPCSTR titleText, LPCSTR labelText, LPCSTR styleSheet, LPCSTR icon) :
QProgressDialog(labelText, CANCEL, 0, 100, QApplication::activeWindow(), 0), m_isCanceled(FALSE), m_indeterminateMode(FALSE), m_lastProgress(-1),
m_hMouseHook(NULL), m_hWinHook(NULL), m_hTimerQueue(NULL), m_hUpdateTimer(NULL)
{
    setWindowTitle(titleText);
    setAutoReset(FALSE);
    setAutoClose(FALSE);
    setWindowModality(Qt::WindowModal);
    setFixedSize(DAILOG_WIDTH, DAILOG_HEIGHT);
    setSizeGripEnabled(FALSE);

    // Qt::Tool      -- Smaller title bar with smaller 'X'
    // Qt::Popup     -- Boarderless
    // Qt::SubWindow -- Nonmodal on top with no background
    //setWindowFlags(Qt::Tool);
    // Nix the title bar help button
    setWindowFlags((windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowMinimizeButtonHint);

    // This time must elapse before dialog shows (default 4sec)
    setMinimumDuration(SHOW_DELAY);

    // Set dialog font (and children inherit)
    QFont fnt(FONT, 10, QFont::Normal);
    fnt.setStyleStrategy(QFont::PreferAntialias);
    setFont(fnt);

    // Put the progress text in the middle
    if (QProgressBar *bar = findChild<QProgressBar *>())
        bar->setAlignment(Qt::AlignCenter);

    // Optionally set Qt style sheet
    if (styleSheet && styleSheet[0])
    {
        // From a file?
        if (strncmp(styleSheet, "url(", 4) == 0)
        {
            QString fn(styleSheet + (sizeof("url(") - 1));
            fn.chop(1);

            QFile f(fn);
            if (f.open(QFile::ReadOnly | QFile::Text))
                setStyleSheet(QTextStream(&f).readAll());
        }
        else
            // No, string
            setStyleSheet(styleSheet);
    }

    // Optionally set titlebar icon
    if (icon && icon[0])
        setWindowIcon(QIcon(icon));

    // Progress 0 for the control to setup internally
    setValue(0);

    // Start update interval timer
    if (m_hTimerQueue = CreateTimerQueue())
        CreateTimerQueueTimer(&m_hUpdateTimer, m_hTimerQueue, (WAITORTIMERCALLBACK) timerTick, NULL, TARGET_UPDATE_MS, TARGET_UPDATE_MS, 0);
    _ASSERT(m_hUpdateTimer != NULL);
}

MyQProgressDialog::~MyQProgressDialog()
{
    if (m_hUpdateTimer)
    {
        DeleteTimerQueueTimer(m_hTimerQueue, m_hUpdateTimer, NULL);
        m_hUpdateTimer = NULL;
    }

    if (m_hTimerQueue)
    {
        DeleteTimerQueueEx(m_hTimerQueue, NULL);
        m_hTimerQueue = NULL;
    }

    if (m_hWinHook)
    {
        UnhookWindowsHookEx(m_hWinHook);
        m_hWinHook = NULL;
    }

    if (m_hMouseHook)
    {
        UnhookWindowsHookEx(m_hMouseHook);
        m_hMouseHook = NULL;
    }
}


// Have to wait till the dialog is actually shown to tweak some things
void MyQProgressDialog::showEvent(QShowEvent *event)
{
    QProgressDialog::showEvent(event);

    // Size and position cancel button
    if (QPushButton *button = findChild<QPushButton *>())
    {
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        button->setFixedSize(BUTTON_WIDTH, BUTTON_HEIGHT);
        #ifndef MATERIAL_DESIGN_STYLE
        const int FROM_BOTTOM = 6;
        #else
        const int FROM_BOTTOM = 10;
        #endif
        button->move(((DAILOG_WIDTH - BUTTON_WIDTH) / 2), ((DAILOG_HEIGHT - BUTTON_HEIGHT) - FROM_BOTTOM));
    }

    // Size and position progress bar
    if (QProgressBar *bar = findChild<QProgressBar *>())
    {
        bar->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        const int BAR_WIDTH = 232;
        #ifndef MATERIAL_DESIGN_STYLE
        bar->setFixedSize(BAR_WIDTH, 21);
        #else
        bar->setFixedSize(BAR_WIDTH, 4);
        #endif
        bar->move(((DAILOG_WIDTH - BAR_WIDTH) / 2), 40); // 41
    }

    // Hook locally some windows events
    m_hMouseHook = SetWindowsHookEx(WH_MOUSE, mouseHook, NULL, GetCurrentThreadId());
    m_hWinHook = SetWindowsHookEx(WH_CALLWNDPROC, msgHook, NULL, GetCurrentThreadId());
    _ASSERT((m_hMouseHook != NULL) && (m_hWinHook != NULL));
}


// Show the modal wait box dialog
void _cdecl WaitBox::show(LPCSTR titleText, LPCSTR labelText, LPCSTR styleSheet, LPCSTR icon)
{
    if (!showState)
    {
        try
        {
            // Create the dialog
            if (prgDlg = new MyQProgressDialog(titleText, labelText, styleSheet, icon))
            {
                // Taskbar progress
                showState = isUpdateReady = TRUE;
                TaskProgress::start(getIdaHwnd());
                TaskProgress::setTrackingWindow((HWND) prgDlg->winId());
            }
        }
        MYCATCH()
    }
}

// Stop the wait box
void _cdecl WaitBox::hide()
{
    if (showState)
    {
        showState = FALSE;
        try
        {
            TaskProgress::end();
            if (prgDlg)
            {
                prgDlg->close();
                delete prgDlg;
                prgDlg = NULL;
            }
        }
        MYCATCH()
    }
}

// Returns TRUE if wait box is up
BOOL _cdecl WaitBox::isShowing()
{
    return(showState && (prgDlg && !prgDlg->isCanceled()));
}

// Returns TRUE if wait box is up
BOOL _cdecl WaitBox::isUpdateTime(){ return(isUpdateReady); }

// Set the label text
void _cdecl WaitBox::setLabelText(LPCSTR labelText)
{
    try
    {
        if (prgDlg && labelText)
            prgDlg->setLabelText(labelText);
    }
    MYCATCH()
}

// Convenience export of the static Qt function "QApplication::processEvents();" to tick IDA's main msg pump
void _cdecl WaitBox::processIdaEvents() { QApplication::processEvents(); }


BOOL MyQProgressDialog::updateAndCancelCheck(int progress)
{
    if (!m_isCanceled && isUpdateReady)
    {
        if (wasCanceled())
        {
            m_isCanceled = isUpdateReady = TRUE;
            TaskProgress::end();
        }
        else
        {
            isUpdateReady = FALSE;
            if (m_indeterminateMode || (progress == -1))
            {
                if (!m_indeterminateMode)
                {
                    // Switch to indeterminateMode mode
                    m_indeterminateMode = TRUE;
                    TaskProgress::setProgress(-1);
                    setRange(0, 0);
                    m_lastProgress = 1;
                }

                // Progress value has to fluctuate for Qt animations to occur
                setValue(m_lastProgress++);
				WaitBox::processIdaEvents();
            }
            else
            {
                if (progress > 100)
                    progress = 100;
                else
                // progress 0 is a special case
                if (progress < 1)
                    progress = 1;

                if (progress != m_lastProgress)
                {
                    setValue(progress);
                    TaskProgress::setProgress(progress);
                    m_lastProgress = progress;
                }
            }

            // Let Qt event queue have a tick
			WaitBox::processIdaEvents();
        }
    }

    return(m_isCanceled);
}

// Check if user canceled and optionally the update progress too w/built-in timed update limiter.
BOOL _cdecl WaitBox::updateAndCancelCheck(int progress)
{
    if (showState)
    {
        if (prgDlg)
        {
            if (isUpdateReady)
                return(prgDlg->updateAndCancelCheck(progress));
            else
                return(FALSE);
        }
    }
	return(FALSE);
}


