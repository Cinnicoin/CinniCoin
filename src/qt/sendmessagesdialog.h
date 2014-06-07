#ifndef SENDMESSAGESDIALOG_H
#define SENDMESSAGESDIALOG_H

#include <QDialog>
#include <QString>

namespace Ui {
    class SendMessagesDialog;
}

class MessageModel;
class SendMessagesEntry;
class SendMessagesRecipient;

//QT_BEGIN_NAMESPACE
//class QUrl;
//QT_END_NAMESPACE

/** Dialog for sending messages */
class SendMessagesDialog : public QDialog
{
    Q_OBJECT

public:

    enum Mode {
        Encrypted,
        Anonymous
    };

    explicit SendMessagesDialog(Mode mode, QWidget *parent = 0);
    ~SendMessagesDialog();

    void setModel (MessageModel *model);
    bool checkMode(Mode mode);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void pasteEntry(const SendMessagesRecipient &rv);
    //bool handleURI(const QString &uri);

public slots:
    void clear();
    void reject();
    void accept();
    SendMessagesEntry *addEntry();
    void updateRemoveEnabled();

private:
    Ui::SendMessagesDialog *ui;
    MessageModel *model;
    bool fNewRecipientAllowed;
    Mode mode;

private slots:
    void on_sendButton_clicked();
    void removeEntry(SendMessagesEntry* entry);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();

};

#endif // SENDMESSAGESDIALOG_H
