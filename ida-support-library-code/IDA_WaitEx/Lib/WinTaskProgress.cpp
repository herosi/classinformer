
// Windows 7+ taskbar progress
// Sirmabus 2015
// http://www.macromonkey.com
#define WIN32_LEAN_AND_MEAN
#define WINVER       _WIN32_WINNT_WIN7
#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define _WIN32_IE_   _WIN32_WINNT_WIN7
#include <Windows.h>
#include <exception>
#include <VersionHelpers.h>
#include <shobjidl.h>

// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

#include "WinTaskProgress.h"

static UINT taskBarButtonMsg = RegisterWindowMessage("TaskbarButtonCreated");
static BOOL indeterminateMode = FALSE;
static HWND hwndOwner = NULL, hwndTrack = NULL;
static ITaskbarList3 *tbi = NULL;

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception in TaskProgress method: %s()! ***\n", __FUNCTION__); }

// Make sure ITaskbarList3 is released on exit if end() wan't called
struct OnExit
{
    ~OnExit() { TaskProgress::end(); }
} static onExit;

void TaskProgress::start(HWND hwnd)
{
    if (hwnd)
    {
        hwndTrack = NULL, indeterminateMode = FALSE;
        try
        {
            // Requires at least Windows 7
            if (IsWindows7OrGreater())
            {
                // Just need to register the message for things to work
                // TODO: Could use a window hook off the main HWND to handle taskBarButtonMsg if really needed
                ChangeWindowMessageFilterEx(hwndOwner = hwnd, taskBarButtonMsg, MSGFLT_ALLOW, NULL);

                // Get ITaskbarList3 interface
                if (SUCCEEDED(CoCreateInstance(CLSID_TaskbarList, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&tbi))))
                {
                    if (SUCCEEDED(tbi->HrInit()))
                        tbi->SetProgressState(hwndOwner, TBPF_NORMAL);
                    else
                    {
                        tbi->Release();
                        tbi = NULL;
                    }
                }
            }
        }
        MYCATCH()
    }
}

void TaskProgress::end()
{
    if (tbi)
    {
        try
        {
            indeterminateMode = FALSE;
            if (hwndTrack)
                tbi->UnregisterTab(hwndTrack);
            tbi->SetProgressState(hwndOwner, TBPF_NOPROGRESS);
            tbi->Release();
            tbi = NULL;
        }
        MYCATCH()
    }
}

void TaskProgress::setProgress(int progress)
{
    if (tbi)
    {
        if (progress < 0)
        {
            // Note: Animation will not occur if animations are unchecked in Windows "Performance Options"
            tbi->SetProgressState(hwndOwner, TBPF_INDETERMINATE);
            indeterminateMode = TRUE;
        }
        else
        if (!indeterminateMode)
        {
            if (progress > 100) progress = 100;
            tbi->SetProgressValue(hwndOwner, (ULONG)progress, (ULONG)100);
        }
    }
}

void TaskProgress::setTrackingWindow(HWND hwnd)
{
    try
    {
        if (tbi && hwnd)
            tbi->RegisterTab(hwndTrack = hwnd, hwndOwner);
        else
            hwndTrack = NULL;
    }
    MYCATCH()
}


