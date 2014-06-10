#ifndef MESSAGEMODEL_H
#define MESSAGEMODEL_H

#include <vector>
#include "allocators.h" /* for SecureString */
#include <map>
#include <QAbstractTableModel>
#include <QStringList>


class MessageTablePriv;
class CWallet;
class WalletModel;
class SecInboxMsg;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendMessagesRecipient
{
public:
    QString address;
    QString label;
    QString pubkey;
    QString message;
};

/** Interface to Cinnicoin Secure Messaging from Qt view code. */
class MessageModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit MessageModel(CWallet *wallet, WalletModel *walletModel, QObject *parent = 0);
    ~MessageModel();

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

    enum ColumnIndex {
        Type = 0,   /**< Sent/Received */
        SentDateTime = 1, /**< Time Sent */
        ReceivedDateTime = 2, /**< Time Received */
        Label = 3,   /**< User specified label */
        ToAddress = 4, /**< To Bitcoin address */
        FromAddress = 5, /**< From Bitcoin address */
        Message = 6, /**< From Bitcoin address */
    };

    enum RoleIndex {
        TypeRole = Qt::UserRole /**< Type of message (#Sent or #Received) */
    };

    static const QString Sent; /**< Specifies sent message */
    static const QString Received; /**< Specifies sent message */

    /** @name Methods overridden from QAbstractTableModel
        @{*/
    int rowCount(const QModelIndex &parent) const;
    int columnCount(const QModelIndex &parent) const;
    QVariant data(const QModelIndex &index, int role) const;
    //bool setData(const QModelIndex & index, const QVariant & value, int role);
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex & parent) const;
    //bool removeRows(int row, int count, const QModelIndex & parent = QModelIndex());
    Qt::ItemFlags flags(const QModelIndex & index) const;
    /*@}*/

    /* Look up row index of a message in the model.
       Return -1 if not found.
     */
    int lookupMessage(const QString &message) const;

    WalletModel *getWalletModel();

    int getNumReceivedMessages() const;
    int getNumSentMessages() const;
    int getNumUnreadMessages() const;
    bool getAddressOrPubkey( QString &Address,  QString &Pubkey) const;

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
    SendMessagesReturn sendMessages(const QList<SendMessagesRecipient> &recipients, const QString &addressFrom);

private:
    CWallet *wallet;
    WalletModel *walletModel;
    QTimer *pollTimer;
    MessageTablePriv *priv;
    QStringList columns;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

public slots:

    /* Check for new messages */
    void pollMessages();
    void updateEntry(SecInboxMsg & smsgInbox);

    friend class MessageTablePriv;

signals:
    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};

#endif // MESSAGEMODEL_H
