
// IDA WaitEx plug-in examples
// By Sirmabus 2015
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Minimal IDA SDK includes
//#define PLUGIN_SUBMODULE
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <idp.hpp>
#include <loader.hpp>
#pragma warning(pop)

// Include this header in your project
//#define MATERIAL_DESIGN_STYLE
#include "WaitBoxEx.h"

#define TEST_TIME_MS (6 * 1000)

bool idaapi run(size_t arg)
{
    /* 
        It should take about two seconds for the boxes to show up.
        Why show a wait box if your plug-in completes in less then two seconds?
        This is a design feature (that's normally 4 seconds) built into QProgressDialog().        
    */

    // ======== Determinate/normal progress
    msg("- Determinate progress example.\n");
   
    // Start up the box with the defaults
    WaitBox::show();
    for (int i = 0; i < 100; i++)
    {
        // Update the progress and check if canceled
        if (WaitBox::updateAndCancelCheck(i))
        {
            // Bail out on cancel
            msg("* Determinate canceled *\n");            
            break;
        }

        Sleep(TEST_TIME_MS / 100);
    }
    // We're done, hide it
    WaitBox::hide();

    // A little delay
    Sleep(1000);

    // ======== Indeterminate progress
    // When you can't determine, or otherwise when it's difficult to calculate, the scope of the progress    
    msg("- Indeterminate progress example.\n");    

    // This time we'll also set the title and label
    WaitBox::show("Indeterminate", "Working..");
    WaitBox::updateAndCancelCheck(-1);
    for (int i = 0; i < 100; i++)
    {
        // This is a preferred way as it has the least amount of overhead
        // (Just the overhead of a the call and single BOOL value check)
        // Particularity important if it were inside of a inner loop, and or
        // in the case where the progress calculation is relatively expensive.
        if (WaitBox::isUpdateTime())
        {
            // Still need this call to check for cancel and to do the bar animation
            if (WaitBox::updateAndCancelCheck())
            {
                msg("* Indeterminate canceled *\n");                
                break;
            }
        }

        Sleep(TEST_TIME_MS / 100);
    }
    WaitBox::hide();
    Sleep(1000);

    // ======== With Qt style sheet visual customizations
    msg("- Progress with style.\n");	

    // Qt CSS style style-sheet
    static const char myStyle[] =
    {
        "QWidget {"
            "background-color: #336666;"
            "color: #ddeeee;"
            "font: bold;"
        "}" 

        "QPushButton {"
            "background-color: #77bbbb;"
            "border-width: 2px;"
            "border-color: #448888;"
            "border-style: solid;"
            "border-radius: 5;"
            "padding: 3px;"
            "min-width: 9ex;"
            "min-height: 2.5ex;"
        "}"
        "QPushButton:hover {"
            "background-color: #99cccc;"
        "}"
        "QPushButton:pressed {"
            "background-color: #55aaaa;"
            "padding-left: 5px;"
            "padding-top: 5px;"
        "}"
      
        "QProgressBar {"
            "background-color: #77bbbb;"
            "border-width: 2px;"
            "border-color: #448888;"
            "border-style: solid;"
            "border-radius: 5;"
        "}"        
        "QProgressBar::chunk {"
            "background-color: #ff8247;"
            "width: 10px;"
            "margin: 0.5px;"
        "}"
    };
       
    WaitBox::show("Styled", "Please wait..", myStyle);
    for (int i = 0; i < 100; i++)
    {
        if (WaitBox::isUpdateTime())
        {
            if (WaitBox::updateAndCancelCheck(i))
            {                
                msg("* Style example canceled *\n");               
                break;
            }
        }

        Sleep(TEST_TIME_MS / 100);
    }   
    WaitBox::hide();

    /*
    // IDA's built-in wait box
    msg("IDA wait box.\n");    
    show_wait_box("Please wait..");
    for (int i = 0; i < 100; i++)
    {       
        if (wasBreak())
        {         
            msg("* Canceled *\n");           
            break;
        }

        Sleep(TEST_TIME_MS / 100);
    } 
    hide_wait_box();   
    */

    msg("That's it for the WaitEx examples.\n\n");
	return TRUE;
}

int idaapi init()
{
    return PLUGIN_KEEP;   
}


__declspec(dllexport) plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,
    init,	              
    NULL,	              
    run,	              
    "",	                  
    "",	                  
    "IDA WaitEx example",
    NULL
};
