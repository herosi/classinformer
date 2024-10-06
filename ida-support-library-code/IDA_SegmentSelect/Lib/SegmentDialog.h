
#pragma once

#include <Windows.h>

#include <QtWidgets/QDialog>
#include "ui_SegmentDialog.h"

#define USE_DANGEROUS_FUNCTIONS
#include <ida.hpp>
#include <idp.hpp>
#include "SegSelect.h"

class SegmentDialog : public QDialog, public Ui::SegSelectDialog
{
    Q_OBJECT
public:
    SegmentDialog(QWidget *parent, UINT flags, LPCSTR title, LPCSTR styleSheet, LPCSTR icon);
	virtual ~SegmentDialog() { Q_CLEANUP_RESOURCE(SegSelectRes);  }
    void saveGeometry() { geom = geometry(); }
    SegSelect::segments *getSelected();

private:
    static QRect geom;

private slots:
    void onDoubleRowClick(int row, int column);
};


