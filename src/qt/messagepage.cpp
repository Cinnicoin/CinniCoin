#include "messagepage.h"
#include "ui_messagepage.h"

#include "messagemodel.h"
//#include "optionsmodel.h"
#include "bitcoingui.h"
//#include "editaddressdialog.h"
#include "csvmodelwriter.h"
#include "guiutil.h"

#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>

MessagePage::MessagePage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MessagePage),
    model(0)
    //optionsModel(0),
    //mode(mode),
    //tab(tab)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC // Icons on push buttons are very uncommon on Mac
    //ui->newAddressButton->setIcon(QIcon());
    //ui->copyToClipboard->setIcon(QIcon());
    ui->deleteButton->setIcon(QIcon());
#endif

#ifndef USE_QRCODE
    //ui->showQRCode->setVisible(false);
#endif

    // Context menu actions
    //QAction *copyLabelAction = new QAction(tr("Copy &Label"), this);
    //QAction *copyAddressAction = new QAction(ui->copyToClipboard->text(), this);
    //QAction *editAction = new QAction(tr("&Edit"), this);
    //QAction *showQRCodeAction = new QAction(ui->showQRCode->text(), this);
    //QAction *signMessageAction = new QAction(ui->signMessage->text(), this);
    //QAction *verifyMessageAction = new QAction(ui->verifyMessage->text(), this);
    deleteAction = new QAction(ui->deleteButton->text(), this);

    // Build context menu
    contextMenu = new QMenu();
    //contextMenu->addAction(copyAddressAction);
    //contextMenu->addAction(copyLabelAction);
    //contextMenu->addAction(editAction);
    //if(tab == SendingTab)
    contextMenu->addAction(deleteAction);
    //contextMenu->addSeparator();
    //contextMenu->addAction(showQRCodeAction);
    //if(tab == ReceivingTab)
    //    contextMenu->addAction(signMessageAction);
    //else if(tab == SendingTab)
    //    contextMenu->addAction(verifyMessageAction);

    // Connect signals for context menu actions
    //connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(on_copyToClipboard_clicked()));
    //connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(onCopyLabelAction()));
    //connect(editAction, SIGNAL(triggered()), this, SLOT(onEditAction()));
    connect(deleteAction, SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));
    //connect(showQRCodeAction, SIGNAL(triggered()), this, SLOT(on_showQRCode_clicked()));
    //connect(signMessageAction, SIGNAL(triggered()), this, SLOT(on_signMessage_clicked()));
    //connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(on_verifyMessage_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));

    // Pass through accept action from button box
    //connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

MessagePage::~MessagePage()
{
    delete ui;
}

void MessagePage::setModel(MessageModel *model)
{
    this->model = model;
    if(!model)
        return;

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
/*
    switch(tab)
    {
    case ReceivingTab:
        // Receive filter
        proxyModel->setFilterRole(AddressTableModel::TypeRole);
        proxyModel->setFilterFixedString(AddressTableModel::Receive);
        break;
    case SendingTab:
        // Send filter
        proxyModel->setFilterRole(AddressTableModel::TypeRole);
        proxyModel->setFilterFixedString(AddressTableModel::Send);
        break;
    }
*/
    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    // Set column widths
    ui->tableView->horizontalHeader()->resizeSection(MessageModel::Type,             100);
    ui->tableView->horizontalHeader()->setResizeMode(MessageModel::Label,            QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->resizeSection(MessageModel::FromAddress,      320);
    ui->tableView->horizontalHeader()->resizeSection(MessageModel::ToAddress,        320);
    ui->tableView->horizontalHeader()->resizeSection(MessageModel::SentDateTime,     160);
    ui->tableView->horizontalHeader()->resizeSection(MessageModel::ReceivedDateTime, 160);
    ui->tableView->horizontalHeader()->setResizeMode(MessageModel::Message,          QHeaderView::Stretch);

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)),
            this, SLOT(selectionChanged()));

    /*
    // Select row for newly created address
    connect(model, SIGNAL(rowsInserted(QModelIndex,int,int)),
            this, SLOT(selectNewAddress(QModelIndex,int,int)));
            */

    selectionChanged();
}

/*
void MessagePage::setOptionsModel(OptionsModel *optionsModel)
{
    this->optionsModel = optionsModel;
}

void MessagePage::on_copyToClipboard_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessageeModel::Address);
}

void AddressBookPage::onCopyLabelAction()
{
    GUIUtil::copyEntryData(ui->tableView, AddressTableModel::Label);
}

void AddressBookPage::onEditAction()
{
    if(!ui->tableView->selectionModel())
        return;
    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();
    if(indexes.isEmpty())
        return;

    EditAddressDialog dlg(
            tab == SendingTab ?
            EditAddressDialog::EditSendingAddress :
            EditAddressDialog::EditReceivingAddress);
    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();
}

void AddressBookPage::on_signMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(AddressTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit signMessage(addr);
}

void AddressBookPage::on_verifyMessage_clicked()
{
    QTableView *table = ui->tableView;
    QModelIndexList indexes = table->selectionModel()->selectedRows(AddressTableModel::Address);
    QString addr;

    foreach (QModelIndex index, indexes)
    {
        QVariant address = index.data();
        addr = address.toString();
    }

    emit verifyMessage(addr);
}

void AddressBookPage::on_newAddressButton_clicked()
{
    if(!model)
        return;
    EditAddressDialog dlg(
            tab == SendingTab ?
            EditAddressDialog::NewSendingAddress :
            EditAddressDialog::NewReceivingAddress, this);
    dlg.setModel(model);
    if(dlg.exec())
    {
        newAddressToSelect = dlg.getAddress();
    }
}
*/
void MessagePage::on_deleteButton_clicked()
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

void MessagePage::selectionChanged()
{
    //QMessageBox::critical(this, ui->tableView->selectionModel()->hasSelection() ? "yes" : "no", "test", QMessageBox::Ok, QMessageBox::Ok);
    // Set button states based on selected tab and selection
    QTableView *table = ui->tableView;
    if(!table->selectionModel())
        return;

    if(table->selectionModel()->hasSelection())
    {
        deleteAction->setEnabled(true);
        ui->deleteButton->setEnabled(true);

        // Figure out which message was selected, and return it
        QModelIndexList indexes = table->selectionModel()->selectedRows(MessageModel::Message);

        foreach (QModelIndex index, indexes)
        {
            QVariant message = table->model()->data(index);

            ui->message->setPlainText(message.toString());
            ui->message->show();
        }

        //ui->copyToClipboard->setEnabled(true);
        //ui->showQRCode->setEnabled(true);
    }
    else
    {
        ui->deleteButton->setEnabled(false);
        ui->message->clear();
        ui->message->hide();
    }
}

void MessagePage::done(int retval)
{
    QTableView *table = ui->tableView;
    if(!table->selectionModel() || !table->model())
        return;
    // When this is a tab/widget and not a model dialog, ignore "done"

    // Figure out which address was selected, and return it
    QModelIndexList indexes = table->selectionModel()->selectedRows(MessageModel::ToAddress);

    foreach (QModelIndex index, indexes)
    {
        QVariant address = table->model()->data(index);
        returnValue = address.toString();
    }

    if(returnValue.isEmpty())
    {
        // If no address entry selected, return rejected
        retval = Rejected;
    }

    QDialog::done(retval);
}

void MessagePage::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Address Book Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull()) return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(proxyModel);
    writer.addColumn("Label", MessageModel::Label, Qt::EditRole);
    writer.addColumn("Address", MessageModel::ToAddress, Qt::EditRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}


void MessagePage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if(index.isValid())
    {
        contextMenu->exec(QCursor::pos());
    }
}
/*
void MessagePage::selectNewAddress(const QModelIndex &parent, int begin, int end)
{
    QModelIndex idx = proxyModel->mapFromSource(model->index(begin, MessageModel::ToAddress, parent));
    if(idx.isValid() && (idx.data(Qt::EditRole).toString() == newAddressToSelect))
    {
        // Select row of newly created address, once
        ui->tableView->setFocus();
        ui->tableView->selectRow(idx.row());
        newAddressToSelect.clear();
    }
}
*/
