#include "invoiceviewpage.h"
#include "ui_invoiceviewpage.h"

#include "messagemodel.h"
#include "bitcoingui.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>

InvoiceViewPage::InvoiceViewPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::InvoiceViewPage)
{
    ui->setupUi(this);
}

InvoiceViewPage::~InvoiceViewPage()
{
    delete ui;
}

void InvoiceViewPage::setModel(InvoiceTableModel *model)
{
    this->model = model->getInvoiceItemTableModel();
    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(this->model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    ui->invoiceItemTableView->setModel(proxyModel);

    // Set column widths
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Code,             100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Description,      320);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Quantity,         100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Tax,              100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Price,            100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Amount,           100);

    connect(ui->invoiceItemTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this, SLOT(selectionChanged()));

    //selectionChanged();
}
