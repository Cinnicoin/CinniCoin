#ifndef INVOICEPAGE_H
#define INVOICEPAGE_H

#include <QDialog>

namespace Ui {
    class InvoicePage;
}

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE

class InvoicePage : public QDialog
{
    Q_OBJECT

public:
    explicit InvoicePage(QWidget *parent = 0);
    ~InvoicePage();

private:
    Ui::InvoicePage *ui;
};

#endif // INVOICEPAGE_H
