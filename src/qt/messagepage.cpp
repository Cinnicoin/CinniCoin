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
    deleteAction = new QAction(ui->deleteButton->text(), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(deleteAction);
    connect(deleteAction, SIGNAL(triggered()), this, SLOT(on_deleteButton_clicked()));

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
    ui->tableView->sortByColumn(2, Qt::AscendingOrder);

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

