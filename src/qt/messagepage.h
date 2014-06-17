#ifndef MESSAGEPAGE_H
#define MESSAGEPAGE_H

#include <QWidget>

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
class MessagePage : public QWidget
{
    Q_OBJECT

public:

    explicit MessagePage(QWidget *parent = 0);
    ~MessagePage();

    void setModel(MessageModel *model);

public slots:
    void exportClicked();

private:
    Ui::MessagePage *ui;
    MessageModel *model;
    QSortFilterProxyModel *proxyModel;
    QMenu *contextMenu;
    QAction *replyAction;
    QAction *copyFromAddressAction;
    QAction *copyToAddressAction;
    QAction *deleteAction;

private slots:
    void on_replyButton_clicked();
    void on_copyFromAddressButton_clicked();
    void on_copyToAddressButton_clicked();
    void on_deleteButton_clicked();
    void selectionChanged();
    /** Spawn contextual menu (right mouse menu) for address book entry */
    void contextualMenu(const QPoint &point);

signals:
};

#endif // MESSAGEPAGE_H
