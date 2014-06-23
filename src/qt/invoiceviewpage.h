#ifndef INVOICEVIEWPAGE_H
#define INVOICEVIEWPAGE_H

#include <QDialog>

namespace Ui {
    class InvoiceViewPage;
}
class InvoiceTableModel;
class InvoiceItemTableModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

class InvoiceViewPage : public QDialog
{
    Q_OBJECT

public:
    explicit InvoiceViewPage(QWidget *parent = 0);
    ~InvoiceViewPage();

    void setModel(InvoiceTableModel *model);
    void loadRow(int row, bool allowEdit = false);
    void newInvoice();

private:
    Ui::InvoiceViewPage *ui;
    InvoiceTableModel *model;
    QSortFilterProxyModel *proxyModel;
    QSortFilterProxyModel *invoiceProxyModel;
    QAction *sendAction;
    bool resend;
    int curRow;

private slots:
    void on_sendButton_clicked();
    void updateTotal();
};

#endif // INVOICEVIEWPAGE_H
