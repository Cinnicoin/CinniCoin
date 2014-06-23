#ifndef RECEIPTPAGE_H
#define RECEIPTPAGE_H

#include <QWidget>

namespace Ui {
    class ReceiptPage;
}
class MessageModel;
class InvoiceTableModel;
class ReceiptTableModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE


/** Widget that shows a list of sending or receiving addresses.
  */
class ReceiptPage : public QWidget
{
    Q_OBJECT

public:

    explicit ReceiptPage(QWidget *parent = 0);
    ~ReceiptPage();

    void setModel(MessageModel *model);

public slots:
    void exportClicked();

private:
    Ui::ReceiptPage *ui;
    ReceiptTableModel *model;
    MessageModel *messageModel;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *replyAction;
    QAction *resendAction;
    QAction *copyFromAddressAction;
    QAction *copyToAddressAction;
    QAction *deleteAction;
    QAction *viewAction;

private slots:
    void on_newButton_clicked();
    void on_replyButton_clicked();
    void on_copyFromAddressButton_clicked();
    void on_copyToAddressButton_clicked();
    void on_deleteButton_clicked();
    void selectionChanged();

    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

signals:
};

#endif // RECEIPTPAGE_H
