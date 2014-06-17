#include "invoiceviewpage.h"
#include "ui_invoiceviewpage.h"

#include "messagemodel.h"
#include "optionsmodel.h"
#include "sendmessagesdialog.h"
#include "bitcoinunits.h"
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
    this->model = model;

    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model->getInvoiceItemTableModel());
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    ui->invoiceItemTableView->setModel(proxyModel);

    // Set column widths
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Code,             100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Description,      320);
    ui->invoiceItemTableView->horizontalHeader()->setResizeMode(InvoiceItemTableModel::Description,      QHeaderView::Stretch);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Quantity,         100);
    //ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Tax,              100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Price,            100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Amount,           100);

    ui->subtotalLabel->setVisible(false);
    ui->taxLabel->setVisible(false);
    ui->subtotal->setVisible(false);
    ui->tax->setVisible(false);

    //connect(ui->invoiceItemTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this, SLOT(selectionChanged()));

    //selectionChanged();
}

void InvoiceViewPage::loadRow(int row)
{
    ui->companyInfoLeft ->setText(model->data(model->index(row, model->CompanyInfoLeft,  QModelIndex()), Qt::DisplayRole).toString());
    ui->companyInfoRight->setText(model->data(model->index(row, model->CompanyInfoRight, QModelIndex()), Qt::DisplayRole).toString());
    ui->billingInfoLeft ->setText(model->data(model->index(row, model->BillingInfoLeft,  QModelIndex()), Qt::DisplayRole).toString());
    ui->billingInfoRight->setText(model->data(model->index(row, model->BillingInfoRight, QModelIndex()), Qt::DisplayRole).toString());
    ui->footer          ->setText(model->data(model->index(row, model->Footer,           QModelIndex()), Qt::DisplayRole).toString());
    ui->dueDate         ->setDate(model->data(model->index(row, model->DueDate,          QModelIndex()), Qt::DisplayRole).toDate());
    ui->invoiceNumber   ->setText(model->data(model->index(row, model->InvoiceNumber,    QModelIndex()), Qt::DisplayRole).toString());
    ui->total           ->setText(model->data(model->index(row, model->Total,            QModelIndex()), Qt::DisplayRole).toString());

    proxyModel->setFilterRole(Qt::UserRole);
    proxyModel->setFilterFixedString(model->data(model->index(row, model->Type, QModelIndex()), Qt::UserRole).toString());

    ui->sendButton->setVisible(false);

    //proxyModel->setFilterRole(Qt::DisplayRole);
    //proxyModel->setFilterFixedString(model->data(model->index(row, model->Type, QModelIndex()), Qt::DisplayRole).toString());
}

void InvoiceViewPage::newInvoice()
{
    /* TODO: Pre-populate...
    ui->companyInfoLeft ->setText(model->data(model->index(row, model->CompanyInfoLeft,  QModelIndex()), Qt::DisplayRole).toString());
    ui->companyInfoRight->setText(model->data(model->index(row, model->CompanyInfoRight, QModelIndex()), Qt::DisplayRole).toString());
    ui->billingInfoLeft ->setText(model->data(model->index(row, model->BillingInfoLeft,  QModelIndex()), Qt::DisplayRole).toString());
    ui->billingInfoRight->setText(model->data(model->index(row, model->BillingInfoRight, QModelIndex()), Qt::DisplayRole).toString());
    ui->footer          ->setText(model->data(model->index(row, model->Footer,           QModelIndex()), Qt::DisplayRole).toString());
    ui->dueDate         ->setDate(model->data(model->index(row, model->DueDate,          QModelIndex()), Qt::DisplayRole).toDate());
    ui->invoiceNumber   ->setText(model->data(model->index(row, model->InvoiceNumber,    QModelIndex()), Qt::DisplayRole).toString());
    ui->total           ->setText(model->data(model->index(row, model->Total,            QModelIndex()), Qt::DisplayRole).toString());
    */

    model->newInvoiceItem();
    proxyModel->setFilterRole(Qt::UserRole);
    proxyModel->setFilterFixedString("new");

    //ui->invoiceItemTableView->set

    ui->sendButton->setVisible(true);

    //proxyModel->setFilterRole(Qt::DisplayRole);
    //proxyModel->setFilterFixedString(model->data(model->index(row, model->Type, QModelIndex()), Qt::DisplayRole).toString());
}

void InvoiceViewPage::on_sendButton_clicked()
{
    if(!model)
        return;

    SendMessagesDialog dlg(SendMessagesDialog::Encrypted, SendMessagesDialog::Dialog, this);

    dlg.setModel(model->getMessageModel());

    dlg.exec();
}
