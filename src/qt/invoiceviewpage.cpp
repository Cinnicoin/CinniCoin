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

    invoiceProxyModel = new QSortFilterProxyModel(this);
    invoiceProxyModel->setSourceModel(model);
    invoiceProxyModel->setDynamicSortFilter(true);
    invoiceProxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    invoiceProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    ui->invoiceItemTableView->setModel(proxyModel);

    // Set column widths
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Code,             100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Description,      320);
    ui->invoiceItemTableView->horizontalHeader()->setResizeMode(InvoiceItemTableModel::Description,      QHeaderView::Stretch);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Quantity,         100);
    //ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Tax,              100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Price,            100);
    ui->invoiceItemTableView->horizontalHeader()->resizeSection(InvoiceItemTableModel::Amount,           100);

    // Hidden columns
    ui->invoiceItemTableView->setColumnHidden(InvoiceItemTableModel::Type, true);

    ui->subtotalLabel->setVisible(false);
    ui->taxLabel->setVisible(false);
    ui->subtotal->setVisible(false);
    ui->tax->setVisible(false);

    connect(model->getInvoiceItemTableModel(), SIGNAL(dataChanged(QModelIndex,QModelIndex,QVector<int>)), this, SLOT(updateTotal()));

    //connect(ui->invoiceItemTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this, SLOT(selectionChanged()));

    //selectionChanged();
}

void InvoiceViewPage::loadRow(int row, bool allowEdit)
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
    proxyModel->setFilterFixedString(model->data(model->index(row, 999, QModelIndex()), Qt::UserRole).toString());

    ui->sendButton->setVisible(allowEdit);
    resend = allowEdit;
    curRow = row;
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

    proxyModel->setFilterRole(Qt::UserRole);
    proxyModel->setFilterFixedString("new");

    if(proxyModel->rowCount() == 0)
    {
        model->newInvoiceItem();
    }

    ui->sendButton->setVisible(true);
}

void InvoiceViewPage::on_sendButton_clicked()
{
    if(!model)
        return;

    SendMessagesDialog dlg(SendMessagesDialog::Encrypted, SendMessagesDialog::Dialog, this);

    dlg.setModel(model->getMessageModel());

    if(resend)
    {
        dlg.loadInvoice(model->getInvoiceJSON(curRow), model->data(model->index(curRow, model->FromAddress,  QModelIndex()), Qt::DisplayRole).toString(), model->data(model->index(curRow, model->ToAddress, QModelIndex()), Qt::DisplayRole).toString());
    }
    else
    {
        model->newInvoice(ui->companyInfoLeft->document()->toPlainText(),
                          ui->companyInfoRight->document()->toPlainText(),
                          ui->billingInfoLeft->document()->toPlainText(),
                          ui->billingInfoRight->document()->toPlainText(),
                          ui->footer->document()->toPlainText(),
                          ui->dueDate->date(),
                          ui->invoiceNumber->text());

        dlg.loadInvoice(model->getInvoiceJSON(0));
    }

    if(dlg.exec() == 0)
        done(0);
}

void InvoiceViewPage::updateTotal()
{
    if(!model)
        return;

    int64 total = 0;
    int rows = proxyModel->rowCount();

    for(int i = 0; i < rows; i++)
    {
        total += proxyModel->data(proxyModel->index(i, InvoiceItemTableModel::Amount), Qt::EditRole).toLongLong();
        if(i+1==rows && proxyModel->data(proxyModel->index(i, InvoiceItemTableModel::Code)).toString() != "")
            model->newInvoiceItem();
    }

    ui->total->setText(BitcoinUnits::formatWithUnit(model->getMessageModel()->getOptionsModel()->getDisplayUnit(), total));
}
