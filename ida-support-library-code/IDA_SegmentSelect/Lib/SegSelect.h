
// SegSelect: IDA Pro Qt multi-segment select dialog
// By Sirmabus 2015
// Version 1.2
// Docs: http://www.macromonkey.com/ida-waitboxex/
// License: Qt 5.6.0 LGPL
#pragma once

#ifndef _LIB
	#ifndef __EA64__
		#ifndef _DEBUG
		#pragma comment(lib, "SegSelect.LiB")
		#else
		#pragma comment(lib, "SegSelectD.LiB")
		#endif
	#else
		#ifndef _DEBUG
		#pragma comment(lib, "SegSelect64.LiB")
		#else
		#pragma comment(lib, "SegSelect64D.LiB")
		#endif
	#endif
#endif

namespace SegSelect
{
    // Option flags
    static const UINT CODE_HINT  = (1 << 0);    // Default check any code segment(s)
    static const UINT DATA_HINT  = (1 << 1);    // Default check any ".data" segment(s)
    static const UINT RDATA_HINT = (1 << 2);    // "" ".rdata" segment(s)
    static const UINT XTRN_HINT  = (1 << 3);    // "" ".idata" type segment(s)

    typedef qlist<segment_t *> segments;

    // Do segment selection dialog
    // Results are returned as a 'segments' vector pointer or NULL if canceled or none selected.
    // Call free() below to free up segments vector.
    segments *select(UINT flags, LPCSTR title = "Choose Segments", LPCSTR styleSheet = NULL, LPCSTR icon = NULL);

    // Free segments vector returned by select()
    void free(segments *list);

    // Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's main window
    void processIdaEvents();
};


