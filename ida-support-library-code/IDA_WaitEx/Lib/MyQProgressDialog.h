
// Subclass of QProgressDialog for customization
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <exception>

#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QProgressBar>

class MyQProgressDialog : public QProgressDialog
{
    Q_OBJECT
public:
    MyQProgressDialog(LPCSTR titleText, LPCSTR labelText, LPCSTR styleSheet, LPCSTR icon);
    ~MyQProgressDialog();
    BOOL updateAndCancelCheck(int progress);
    BOOL isCanceled() { return(m_isCanceled); }

private:
    void showEvent(QShowEvent *event);

    int    m_lastProgress;
    BOOL   m_isCanceled, m_indeterminateMode;
    HHOOK  m_hMouseHook, m_hWinHook;
    HANDLE m_hTimerQueue, m_hUpdateTimer;
};

