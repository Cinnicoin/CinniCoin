#include "messagepage.h"
#include "ui_messagepage.h"

#include "sendmessagesdialog.h"
#include "messagemodel.h"
#include "bitcoingui.h"
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
    replyAction           = new QAction(ui->replyButton->text(),           this);
    copyFromAddressAction = new QAction(ui->copyFromAddressButton->text(), this);
    copyToAddressAction   = new QAction(ui->copyToAddressButton->text(),   this);
    deleteAction          = new QAction(ui->deleteButton->text(),          this);

    // Build context menu
    contextMenu = new QMenu();

    contextMenu->addAction(replyAction);
    contextMenu->addAction(copyFromAddressAction);
    contextMenu->addAction(copyToAddressAction);
    contextMenu->addAction(deleteAction);

    connect(replyAction,           SIGNAL(triggered()), this, SLOT(on_replyButton_clicked()));
    connect(copyFromAddressAction, SIGNAL(triggered()), this, SLOT(on_copyFromAddressButton_clicked()));
    connect(copyToAddressAction,   SIGNAL(triggered()), this, SLOT(on_copyToAddressButton_clicked()));
    connect(deleteAction,          SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
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

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(2, Qt::DescendingOrder);

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

    selectionChanged();
}

void MessagePage::on_replyButton_clicked()
{
    if(!model)
        return;

    if(!ui->tableView->selectionModel())
        return;

    QModelIndexList indexes = ui->tableView->selectionModel()->selectedRows();

    if(indexes.isEmpty())
        return;

    SendMessagesDialog dlg(SendMessagesDialog::Encrypted, SendMessagesDialog::Dialog, this);

    dlg.setModel(model);
    QModelIndex origIndex = proxyModel->mapToSource(indexes.at(0));
    dlg.loadRow(origIndex.row());
    dlg.exec();

}

void MessagePage::on_copyFromAddressButton_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessageModel::FromAddress, Qt::DisplayRole);
}

void MessagePage::on_copyToAddressButton_clicked()
{
    GUIUtil::copyEntryData(ui->tableView, MessageModel::ToAddress, Qt::DisplayRole);
}

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

        ui->messageDetails->show();

        // Figure out which message was selected, and return it
        QModelIndexList messageColumn = table->selectionModel()->selectedRows(MessageModel::Message);
        QModelIndexList labelColumn   = table->selectionModel()->selectedRows(MessageModel::Label);
        QModelIndexList typeColumn    = table->selectionModel()->selectedRows(MessageModel::Type);

        foreach (QModelIndex index, messageColumn)
        {
            ui->message->setPlainText(table->model()->data(index).toString());
        }

        foreach (QModelIndex index, typeColumn)
        {
            ui->labelType->setText(table->model()->data(index).toString());
        }

        foreach (QModelIndex index, labelColumn)
        {
            ui->contactLabel->setText(table->model()->data(index).toString());
        }
    }
    else
    {
        ui->replyButton->setEnabled(false);
        ui->copyFromAddressButton->setEnabled(false);
        ui->copyToAddressButton->setEnabled(false);
        ui->deleteButton->setEnabled(false);
        ui->messageDetails->hide();
        ui->message->clear();
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

// TODO: Export Messages
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

