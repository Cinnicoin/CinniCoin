#ifndef MESSAGEMODEL_H
#define MESSAGEMODEL_H

#include <QObject>
#include <vector>
#include "allocators.h" /* for SecureString */
#include <map>

class CMessage;
class CWallet;
//class CKeyID;
//class CPubKey;
//class COutput;
//class COutPoint;
//class uint256;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE


class WalletModel;
class SendMessagesRecipient
{
public:
    QString address;
    QString label;
    QString pubkey;
    QString message;

};

/** Interface to Cinnicoin Secure Messaging from Qt view code. */
class MessageModel : public QObject
{
    Q_OBJECT

public:
    explicit MessageModel(CWallet *wallet, QObject *parent = 0);
    ~MessageModel();

    WalletModel *walletModel;

    enum StatusCode // Returned by sendMessages
    {
        OK,
        InvalidAddress,
        InvalidMessage,
        DuplicateAddress,
        MessageCreationFailed, // Error returned when DB is still locked
        MessageCommitFailed,
        Aborted
    };

    int getNumReceivedMessages() const;
    int getNumSentMessages() const;
    int getNumUnreadMessages() const;

    // Check address for validity
    //bool validateAddress(const QString &address);

    // Return status record for SendMessages, contains error id + information
    struct SendMessagesReturn
    {
        SendMessagesReturn(StatusCode status=Aborted,
                           QString hex=QString()):
            status(status), hex(hex) {}
        StatusCode status;
        QString hex; // is filled with the message hash if status is "OK"
    };

    // Send messages to a list of recipients
    SendMessagesReturn sendMessages(const QList<SendMessagesRecipient> &recipients);

private:
//    /CMessage *message;
    CWallet *wallet;
    QTimer *pollTimer;

    //void subscribeToCoreSignals();
    //void unsubscribeFromCoreSignals();

public slots:

    /* Check for new messages */
    void pollMessages();

signals:
    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};

#endif // MESSAGEMODEL_H
