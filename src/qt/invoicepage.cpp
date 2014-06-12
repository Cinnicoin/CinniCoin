#include "invoicepage.h"
#include "ui_invoicepage.h"

#include "bitcoingui.h"
#include "guiutil.h"

InvoicePage::InvoicePage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InvoicePage)
{
    ui->setupUi(this);
}

InvoicePage::~InvoicePage()
{
    delete ui;
}
