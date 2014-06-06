#ifndef SENDMESSAGESENTRY_H
#define SENDMESSAGESENTRY_H

#include <QFrame>

namespace Ui {
    class SendMessagesEntry;
}
class WalletModel;
class SendCoinsRecipient;

/** A single entry in the dialog for sending bitcoins. */
class SendMessagesEntry : public QFrame
{
    Q_OBJECT

public:
    explicit SendMessagesEntry(QWidget *parent = 0);
    ~SendMessagesEntry();

    void setModel(WalletModel *model);
    bool validate();
    SendCoinsRecipient getValue();

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient &value);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setFocus();

public slots:
    void setRemoveEnabled(bool enabled);
    void clear();
    
signals:
    void removeEntry(SendMessagesEntry *entry);
    void payAmountChanged();
private slots:
    void on_deleteButton_clicked();
    void on_payTo_textChanged(const QString &address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();

private:
    Ui::SendMessagesEntry *ui;
    WalletModel *model;
};

#endif // SENDMESSAGESENTRY_H
