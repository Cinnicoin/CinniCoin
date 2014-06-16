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

private:
    Ui::InvoiceViewPage *ui;
    InvoiceItemTableModel *model;
    QSortFilterProxyModel *proxyModel;
};

#endif // INVOICEVIEWPAGE_H
