#ifndef MESSAGEMODEL_H
#define MESSAGEMODEL_H

#include "uint256.h"

#include <vector>
#include "allocators.h" /* for SecureString */
#include "emessage.h"
#include <map>
#include <QAbstractTableModel>
#include <QStringList>
#include <QDateTime>


class MessageTablePriv;
class CWallet;
class WalletModel;

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

struct MessageTableEntry
{
    enum Type {
        Sent,
        Received
    };

    std::vector<unsigned char> vchKey;
    Type type;
    QString label;
    QString to_address;
    QString from_address;
    QDateTime sent_datetime;
    QDateTime received_datetime;
    QString message;

    MessageTableEntry() {}
    MessageTableEntry(const std::vector<unsigned char> vchKey, Type type, const QString &label, const QString &to_address, const QString &from_address,
                      const QDateTime &sent_datetime, const QDateTime &received_datetime, const QString &message):
        vchKey(vchKey), type(type), label(label), to_address(to_address), from_address(from_address), sent_datetime(sent_datetime), received_datetime(received_datetime),
        message(message) {}
};

struct InvoiceItemTableEntry
{

    std::vector<unsigned char> vchKey;
    QString code;
    QString description;
    int     quantity;
    int64   rate;
    bool    tax;
    int64   amount;

    InvoiceItemTableEntry() {}
    InvoiceItemTableEntry(const std::vector<unsigned char> vchKey, const QString &code, const QString &description, const int &quantity, const int64 &rate, const bool &tax, const int64 &amount):
        vchKey(vchKey), code(code), description(description), quantity(quantity), rate(rate), tax(tax), amount(amount) {}
};

struct InvoiceTableEntry
{
    enum Type {
        Sent,
        Received
    };

    std::vector<unsigned char> vchKey;
    Type type;
    QString label;
    QString to_address;
    QString from_address;
    QDateTime sent_datetime;
    QDateTime received_datetime;
    QString company_info_left;
    QString company_info_right;
    QString billing_info_left;
    QString billing_info_right;
    QString invoice_number;
    QDate   due_date;
    InvoiceItemTableEntry item;

    InvoiceTableEntry() {}
    InvoiceTableEntry(const std::vector<unsigned char> vchKey, Type type, const QString &label, const QString &to_address, const QString &from_address,
                      const QDateTime &sent_datetime, const QDateTime &received_datetime, const QString &company_info_left, const QString &company_info_right,
                      const QString &billing_info_left, const QString &billing_info_right, const QString &invoice_number, const QDate &due_date, const InvoiceItemTableEntry &item):
        vchKey(vchKey), type(type), label(label), to_address(to_address), from_address(from_address), sent_datetime(sent_datetime), received_datetime(received_datetime),
        company_info_left(company_info_left), company_info_right(company_info_right), billing_info_left(billing_info_left), billing_info_right(billing_info_right),
        invoice_number(invoice_number), due_date(due_date), item(item)
    {}
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
        Message = 6, /**< Plaintext */
        TypeInt = 7,
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
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    QModelIndex index(int row, int column, const QModelIndex & parent) const;
    bool removeRows(int row, int count, const QModelIndex & parent = QModelIndex());
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

    // Send messages to a list of recipients
    StatusCode sendMessages(const QList<SendMessagesRecipient> &recipients);
    StatusCode sendMessages(const QList<SendMessagesRecipient> &recipients, const QString &addressFrom);

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
    void newMessage(const SecInboxMsg& smsgInbox);
    void newOutboxMessage(const SecOutboxMsg& smsgOutbox);

    friend class MessageTablePriv;
    friend class InvoiceTablePriv;

signals:
    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};

#endif // MESSAGEMODEL_H
