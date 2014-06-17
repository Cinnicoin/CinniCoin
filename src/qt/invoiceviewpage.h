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
    void loadRow(int row);
    void newInvoice();

private:
    Ui::InvoiceViewPage *ui;
    InvoiceTableModel *model;
    QSortFilterProxyModel *proxyModel;
    QAction *sendAction;

private slots:
    void on_sendButton_clicked();
};

#endif // INVOICEVIEWPAGE_H
