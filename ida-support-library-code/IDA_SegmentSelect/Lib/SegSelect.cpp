
// SegSelect: IDA Pro Qt multi-segment select dialog
// By Sirmabus 2015
// Docs: http://www.macromonkey.com/ida-waitboxex/
// License: Qt LGPL
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>

#define QT_NO_STATUSTIP
#define QT_NO_WHATSTHIS
#define QT_NO_ACCESSIBILITY
#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QTableWidget>

#define USE_DANGEROUS_FUNCTIONS
// Nix the many warning about int type conversions
#pragma warning(push)
#pragma warning(disable:4244)
#pragma warning(disable:4267)
#include <ida.hpp>
#include <idp.hpp>
#include "SegmentDialog.h"
#pragma warning(pop)

// IDA SDK Qt libs @ (SDK)\lib\x86_win_qt
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception @ SegSelect in method: %s()! ***\n", __FUNCTION__); }
#define SIZESTR(x) (sizeof(x) - 1)

// QT_NO_UNICODE_LITERAL must be defined (best in preprocessor setting)
// So Qt doesn't a static string pool that will cause IDA to crash on unload
#ifndef QT_NO_UNICODE_LITERAL
# error QT_NO_UNICODE_LITERAL must be defined to avoid Qt string crashes
#endif

QRect SegmentDialog::geom;

SegmentDialog::SegmentDialog(QWidget *parent, UINT flags, LPCSTR title, LPCSTR styleSheet, LPCSTR icon) : QDialog(parent)
{
    // Required for static library resources
    Q_INIT_RESOURCE(SegSelectRes);

    setupUi(this);
	buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
	buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);
    setWindowTitle(title);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    if (icon && icon[0])
        setWindowIcon(QIcon(icon));
    else
        setWindowIcon(QIcon(":/seglib/idaq_seg.png"));

    // Enumerate segments, populate table
	if (int count = get_segm_qty())
	{
		// 1st pass get max character sizes for proportional formating
		int biggestStart = 0, biggestEnd = 0, biggestSize = 0;
		for (int i = 0; i < count; i++)
		{
			segment_t *seg = getnseg(i);
			char buffer[34];
			int len = strlen(_ui64toa(seg->start_ea, buffer, 16));
			if (len > biggestStart) biggestStart = len;
			len = strlen(_ui64toa(seg->end_ea, buffer, 16));
			if (len > biggestEnd) biggestEnd = len;
			len = strlen(_ui64toa(seg->size(), buffer, 16));
			if (len > biggestSize) biggestSize = len;
		}

		#ifndef __EA64__
        if (++biggestStart > 8) biggestStart = 8;
        if (++biggestEnd > 8)   biggestEnd = 8;
        if (++biggestSize > 8)  biggestSize = 8;
        char startFormat[18], endFormat[18], sizeFormat[18];
        sprintf(startFormat, "%%0%dX", biggestStart);
        sprintf(endFormat,   "%%0%dX", biggestEnd);
        sprintf(sizeFormat,  "%%0%dX", biggestSize);
        #else
        if (++biggestStart > 16) biggestStart = 16;
        if (++biggestEnd > 16)   biggestEnd = 16;
        if (++biggestSize > 16)  biggestSize = 16;
        char startFormat[34], endFormat[34], sizeFormat[34];
        sprintf(startFormat, "%%0%dI64X", biggestStart);
        sprintf(endFormat, "%%0%dI64X", biggestEnd);
        sprintf(sizeFormat, "%%0%dI64X", biggestSize);
        #endif

        enum {NAME, TYPE, FLAGS, START, END, SIZE};
        //const int ROW_HEIGHT = 36; // 64dp

        // 2nd pass populate view
        segmentTable->setRowCount(count);
        segmentTable->setUpdatesEnabled(FALSE);
        for (int i = 0; i < count; i++)
        {
            // Name w/checkbox
            segment_t *seg = getnseg(i);

			char buffer[128];
			qstring segName;
			if (get_segm_name(&segName, seg, 0) > 0)
				strncpy_s(buffer, sizeof(buffer), segName.c_str(), SIZESTR(buffer));
			else
                strcpy(buffer, "none");

            QTableWidgetItem *item = new QTableWidgetItem(buffer);
            LPCSTR iconFile;
            BOOL checked = FALSE;
            switch (seg->type)
            {
                case SEG_XTRN:
                {
                    iconFile = ":/seglib/extrn_seg.png";
                    checked = (flags & SegSelect::XTRN_HINT);
                }
                break;

                case SEG_CODE:
                {
                    iconFile = ":/seglib/code_seg.png";
                    checked = (flags & SegSelect::CODE_HINT);
                }
                break;

                case SEG_DATA:
                {
                    iconFile = ":/seglib/data_seg.png";

                    if ((flags & SegSelect::RDATA_HINT) && (strcmp(buffer, ".rdata") == 0))
                        checked = TRUE;
                    else
                    if (flags & SegSelect::DATA_HINT)
                    {
                        // Filter out some common data types we normally don't want hinted
                        static const char *filter[] =
                        {
                            "HEADER", ".rsrc", ".tls", ".reloc",
                        };
                        static const int FILTERED = (sizeof(filter) / sizeof(const char *));

                        int j = 0;
                        for (; j < FILTERED; j++)
                        {
                            if (strcmp(buffer, filter[j]) == 0)
                                break;

                        }
                        checked = (j >= FILTERED);
                    }
                }
                break;
                default: iconFile = ":/seglib/other_seg.png"; break;
            };
            item->setIcon(QIcon(iconFile));
            item->setCheckState(checked ? Qt::Checked : Qt::Unchecked);
            segmentTable->setItem(i, NAME, item);

            // Main types seen on PC are: CODE, DATA, XTRN, some times BSS
            // Oddity in IDA the get_segm_class() will be 'DATA' for .idata segs even
            // though they are the type SEG_XTRN.
            // Going by type instead:
            static const char *typeName[] =
            {
                "NORM",     // 0
                "XTRN",     // 1 *
                "CODE",     // 2 *
                "DATA",     // 3 *
                "JVIMP",    // 4
                "???",      // 5
                "GROUP",    // 6
                "NULL",     // 7
                "UNDEF",    // 8
                "BSS",      // 9 *
                "ABSSYM",   // 10
                "COMM",     // 11
                "IMEM "     // 12
            };
            //if (get_segm_class(seg, buffer, SIZESTR(buffer)) <= 0)
            //    strcpy(buffer, "none");
            if (seg->type <= 12)
                segmentTable->setItem(i, TYPE, new QTableWidgetItem(typeName[seg->type]));
            else
                segmentTable->setItem(i, TYPE, new QTableWidgetItem("???"));

            // Flags "RWE"
            strcpy(buffer, "[...]");
            if (seg->perm & SEGPERM_READ)  buffer[1] = 'R';
            if (seg->perm & SEGPERM_WRITE) buffer[2] = 'W';
            if (seg->perm & SEGPERM_EXEC)  buffer[3] = 'E';
            segmentTable->setItem(i, FLAGS, new QTableWidgetItem(buffer));

            // Start - End, Size
            sprintf(buffer, startFormat, seg->start_ea);
            segmentTable->setItem(i, START, new QTableWidgetItem(buffer));
            sprintf(buffer, endFormat, seg->end_ea);
            segmentTable->setItem(i, END, new QTableWidgetItem(buffer));
            sprintf(buffer, sizeFormat, seg->size());
            segmentTable->setItem(i, SIZE, new QTableWidgetItem(buffer));

            //segmentTable->verticalHeader()->resizeSection(i, ROW_HEIGHT);
        }

        // Restore per session geometry
        if (geom.bottom() != -1)
            setGeometry(geom);

        segmentTable->resizeRowsToContents();
        segmentTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        segmentTable->resizeColumnsToContents();
        segmentTable->setUpdatesEnabled(TRUE);

        // Optionally set a Qt CSS type style sheet
        if (styleSheet && styleSheet[0])
        {
            // Load from file?
            if (strncmp(styleSheet, "url(", 4) == 0)
            {
                QString fn(styleSheet + (sizeof("url(") - 1));
                fn.chop(1);

                QFile f(fn);
                if (f.open(QFile::ReadOnly | QFile::Text))
                    setStyleSheet(QTextStream(&f).readAll());
            }
            else
                setStyleSheet(styleSheet);
        }

        segmentTable->connect(segmentTable, SIGNAL(cellDoubleClicked(int, int)), this, SLOT(onDoubleRowClick(int, int)));
    }
    else
        msg(__FUNCTION__": No segments in this IDB?\n");
}

// Toggle check box on double click row
void SegmentDialog::onDoubleRowClick(int row, int column)
{
    if (QTableWidgetItem *item = segmentTable->item(row, 0))
        item->setCheckState((item->checkState() == Qt::Checked) ? Qt::Unchecked : Qt::Checked);
}

SegSelect::segments *SegmentDialog::getSelected()
{
    SegSelect::segments *result = new SegSelect::segments();
    int count = segmentTable->rowCount();
    for (int i = 0; i < count; i++)
    {
        if (QTableWidgetItem *item = segmentTable->item(i, 0))
            if (item->checkState() == Qt::Checked)
                result->push_front(getnseg(i));
    }
    return(result);
}


// Do segment selection dialog
SegSelect::segments *SegSelect::select(UINT flags, LPCSTR title, LPCSTR styleSheet, LPCSTR icon)
{
	SegSelect::segments *result = NULL;
    try
    {
        SegmentDialog *dlg = new SegmentDialog(QApplication::activeWindow(), flags, title, styleSheet, icon);
        if (dlg->exec())
        {
            // Save geometry for restoration during the plugin session
            dlg->saveGeometry();

            // Return vector of segment pointers
			result = dlg->getSelected();
        }
		delete dlg;
    }
    MYCATCH()
    return(result);
}


// Free segments vector returned by select()
void SegSelect::free(segments *list)
{
    if (list)
    {
        try
        {
            delete list;
        }
        MYCATCH()
    }
}

// Convenience export of the static Qt function "QApplication::processEvents();" to tick IDA's main msg pump
void SegSelect::processIdaEvents() { QApplication::processEvents(); }



