#ifndef INVOICEPAGE_H
#define INVOICEPAGE_H

#include <QWidget>

namespace Ui {
    class InvoicePage;
}
class MessageModel;
class InvoiceTableModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE


/** Widget that shows a list of sending or receiving addresses.
  */
class InvoicePage : public QWidget
{
    Q_OBJECT

public:

    explicit InvoicePage(QWidget *parent = 0);
    ~InvoicePage();

    void setModel(MessageModel *model);

public slots:
    void exportClicked();

private:
    Ui::InvoicePage *ui;
    InvoiceTableModel *model;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *replyAction;
    QAction *payAction;
    QAction *resendAction;
    QAction *copyFromAddressAction;
    QAction *copyToAddressAction;
    QAction *deleteAction;
    QAction *viewAction;

private slots:
    void on_newButton_clicked();
    void on_payButton_clicked();
    void on_replyButton_clicked();
    void on_copyFromAddressButton_clicked();
    void on_copyToAddressButton_clicked();
    void on_deleteButton_clicked();
    void selectionChanged();
    void viewInvoice(const QModelIndex & index);

    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

signals:
};

#endif // INVOICEPAGE_H
