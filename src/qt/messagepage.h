#ifndef MESSAGEPAGE_H
#define MESSAGEPAGE_H

#include <QDialog>

namespace Ui {
    class MessagePage;
}
class MessageModel;
//class OptionsModel;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
QT_END_NAMESPACE


/** Widget that shows a list of sending or receiving addresses.
  */
class MessagePage : public QDialog
{
    Q_OBJECT

public:

    explicit MessagePage(QWidget *parent = 0);
    ~MessagePage();

    void setModel(MessageModel *model);
    const QString &getReturnValue() const { return returnValue; }

public slots:
    void done(int retval);
    void exportClicked();

private:
    Ui::MessagePage *ui;
    MessageModel *model;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction;

private slots:
    void on_deleteButton_clicked();
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

signals:
};

#endif // MESSAGEPAGE_H
