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
    //void setOptionsModel(OptionsModel *optionsModel);
    const QString &getReturnValue() const { return returnValue; }

public slots:
    void done(int retval);
    void exportClicked();

private:
    Ui::MessagePage *ui;
    MessageModel *model;
    //OptionsModel *optionsModel;
    //Mode mode;
    //Tabs tab;
    QString returnValue;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *deleteAction;
    //QString newAddressToSelect;

private slots:
    void on_deleteButton_clicked();
    /** Copy address of currently selected address entry to clipboard */
    //void on_copyToClipboard_clicked();
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

    /** Copy label of currently selected address entry to clipboard */
    //void onCopyLabelAction();
    /** Edit currently selected address entry */
    //void onEditAction();

    /** New entry/entries were added to address table */
    //void selectNewAddress(const QModelIndex &parent, int begin, int end);

signals:
    //void signMessage(QString addr);
    //void verifyMessage(QString addr);
};

#endif // MESSAGEPAGE_H
