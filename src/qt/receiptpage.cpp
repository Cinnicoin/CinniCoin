#include "receiptpage.h"
#include "ui_receiptpage.h"

#include "bitcoinunits.h"
#include "sendmessagesdialog.h"
#include "invoiceviewpage.h"
#include "messagemodel.h"
#include "bitcoingui.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

ReceiptPage::ReceiptPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ReceiptPage),
    model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    ui->deleteButton->setIcon(QIcon());
#endif

    // Context menu actions
    replyAction           = new QAction(ui->replyButton->text(),           this);
    resendAction          = new QAction(ui->resendButton->text(),          this);
    copyFromAddressAction = new QAction(ui->copyFromAddressButton->text(), this);
    copyToAddressAction   = new QAction(ui->copyToAddressButton->text(),   this);
    deleteAction          = new QAction(ui->deleteButton->text(),          this);
    //viewAction            = new QAction(tr("&View Invoice"),               this);

    // Build context menu
    contextMenu = new QMenu();

    contextMenu->addAction(replyAction);
    contextMenu->addAction(copyFromAddressAction);
    contextMenu->addAction(copyToAddressAction);
    contextMenu->addAction(deleteAction);
    //contextMenu->addAction(viewAction);

    connect(resendAction,          SIGNAL(triggered()), this, SLOT(on_replyButton_clicked()));
    connect(replyAction,           SIGNAL(triggered()), this, SLOT(on_replyButton_clicked()));
    connect(copyFromAddressAction, SIGNAL(triggered()), this, SLOT(on_copyFromAddressButton_clicked()));
    connect(copyToAddressAction,   SIGNAL(triggered()), this, SLOT(on_copyToAddressButton_clicked()));
    connect(deleteAction,          SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));

    //connect(viewAction,            SIGNAL(triggered()), this, SLOT(on_doubleclick()));
    //connect(ui->tableView,         SIGNAL (doubleClicked(const QModelIndex&)), this, SLOT (viewInvoice(const QModelIndex&)));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
}

ReceiptPage::~ReceiptPage()
{
    delete ui;
}

void ReceiptPage::setModel(MessageModel *model)
{
    this->model = model->getReceiptTableModel();
    this->messageModel = model;

    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(this->model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    ui->tableView->setModel(proxyModel);

    ui->tableView->sortByColumn(2, Qt::DescendingOrder);

    // Set column widths
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::Type,             100);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::Label,            100);
    ui->tableView->horizontalHeader()->setResizeMode(ReceiptTableModel::Label,            QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::FromAddress,      320);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::ToAddress,        320);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::SentDateTime,     170);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::ReceivedDateTime, 170);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::InvoiceNumber,    100);
    ui->tableView->horizontalHeader()->resizeSection(ReceiptTableModel::Amount,           130);

    // Hidden columns
    ui->tableView->setColumnHidden(ReceiptTableModel::Outstanding,  true);

    ui->newButton->setVisible(false);
    ui->resendButton->setVisible(false);

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this, SLOT(selectionChanged()));

    selectionChanged();
}


void ReceiptPage::on_newButton_clicked()
{
    InvoiceViewPage dlg(this);
    dlg.setModel(messageModel->getInvoiceTableModel());
    dlg.newInvoice();
    dlg.exec();
}

void ReceiptPage::on_replyButton_clicked()
{
    if(!model)
        return;

    if(!ui->tableView->selectionModel())
        return;

    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();

    if(indexes.isEmpty())
        return;

    SendMessagesDialog dlg(SendMessagesDialog::Encrypted, SendMessagesDialog::Dialog, this);

    dlg.setModel(messageModel);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadInvoice("", model->data(model->index(origIndex.row(), model->FromAddress,  QModelIndex()), Qt::DisplayRole).toString(), model->data(model->index(origIndex.row(), model->ToAddress,  QModelIndex()), Qt::DisplayRole).toString());
    dlg.exec();
}

void ReceiptPage::on_copyFromAddressButton_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessageModel::FromAddress, Qt::DisplayRole);
}

void ReceiptPage::on_copyToAddressButton_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessageModel::ToAddress, Qt::DisplayRole);
}

void ReceiptPage::on_deleteButton_clicked()
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;
    QModelIndexList indexes = table->selectionModel()->selectedRows();
    if(!indexes.isEmpty())
    {
        table->model()->removeRow(indexes.at(0).row());
    }
}

void ReceiptPage::selectionChanged()
{
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        replyAction->setEnabled(true);
        copyFromAddressAction->setEnabled(true);
        copyToAddressAction->setEnabled(true);
        deleteAction->setEnabled(true);

        ui->copyFromAddressButton->setEnabled(true);
        ui->copyToAddressButton->setEnabled(true);
        ui->replyButton->setEnabled(true);
        ui->deleteButton->setEnabled(true);

        // Figure out which message was selected, and return it
        QModelIndexList typeColumn = table->selectionModel()->selectedRows(InvoiceTableModel::Type);

        foreach (QModelIndex index, typeColumn)
        {
            bool sent = (table->model()->data(index).toString() == MessageModel::Sent);

            resendAction->setEnabled(sent);
            ui->resendButton->setEnabled(sent);
            ui->resendButton->setVisible(sent);
        }

    }
    else
    {
        ui->replyButton->setEnabled(false);
        ui->resendButton->setEnabled(false);
        ui->copyFromAddressButton->setEnabled(false);
        ui->copyToAddressButton->setEnabled(false);
        ui->deleteButton->setEnabled(false);
    }
}

void ReceiptPage::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Messages"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Type",             MessageModel::Type,             Qt::DisplayRole);
    writer.addColumn("Label",            MessageModel::Label,            Qt::DisplayRole);
    writer.addColumn("FromAddress",      MessageModel::FromAddress,      Qt::DisplayRole);
    writer.addColumn("ToAddress",        MessageModel::ToAddress,        Qt::DisplayRole);
    writer.addColumn("SentDateTime",     MessageModel::SentDateTime,     Qt::DisplayRole);
    writer.addColumn("ReceivedDateTime", MessageModel::ReceivedDateTime, Qt::DisplayRole);
    writer.addColumn("Message",          MessageModel::Message,          Qt::DisplayRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}


void ReceiptPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}



