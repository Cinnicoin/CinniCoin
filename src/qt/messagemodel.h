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
class InvoiceTableModel;
class InvoiceItemTableModel;
class CWallet;
class WalletModel;
class OptionsModel;

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
        TypeInt = 7, /**< Plaintext */
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
    OptionsModel *getOptionsModel();
    InvoiceTableModel *getInvoiceTableModel();

    bool getAddressOrPubkey( QString &Address,  QString &Pubkey) const;

    // Send messages to a list of recipients
    StatusCode sendMessages(const QList<SendMessagesRecipient> &recipients);
    StatusCode sendMessages(const QList<SendMessagesRecipient> &recipients, const QString &addressFrom);

private:
    CWallet *wallet;
    WalletModel *walletModel;
    OptionsModel *optionsModel;
    MessageTablePriv *priv;
    InvoiceTableModel *invoiceTableModel;
    QStringList columns;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

public slots:

    /* Check for new messages */
    void newMessage(const SecInboxMsg& smsgInbox);
    void newOutboxMessage(const SecOutboxMsg& smsgOutbox);

    friend class MessageTablePriv;

signals:
    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};


struct InvoiceItemTableEntry
{

    std::vector<unsigned char> vchKey;
    QString code;
    QString description;
    int     quantity;
    int64   price;
    //bool    tax;

    InvoiceItemTableEntry(){};
    InvoiceItemTableEntry(const bool newInvoice):
        vchKey(0), code(""), description(""), quantity(0), price(0){};
    InvoiceItemTableEntry(const std::vector<unsigned char> vchKey, const QString &code, const QString &description, const int &quantity, const int64 &price): //, const bool &tax):
        vchKey(vchKey), code(code), description(description), quantity(quantity), price(price) {} //, tax(tax) {}
};


struct InvoiceTableEntry
{
    std::vector<unsigned char> vchKey;
    MessageTableEntry::Type type;
    QString label;
    QString to_address;
    QString from_address;
    QDateTime sent_datetime;
    QDateTime received_datetime;
    QString company_info_left;
    QString company_info_right;
    QString billing_info_left;
    QString billing_info_right;
    QString footer;
    QString invoice_number;
    QDate   due_date;

    InvoiceTableEntry() {}
    InvoiceTableEntry(const std::vector<unsigned char> vchKey, MessageTableEntry::Type type, const QString &label, const QString &to_address, const QString &from_address,
                      const QDateTime &sent_datetime, const QDateTime &received_datetime, const QString &company_info_left, const QString &company_info_right,
                      const QString &billing_info_left, const QString &billing_info_right, const QString &footer, const QString &invoice_number, const QDate &due_date):
        vchKey(vchKey), type(type), label(label), to_address(to_address), from_address(from_address), sent_datetime(sent_datetime), received_datetime(received_datetime),
        company_info_left(company_info_left), company_info_right(company_info_right), billing_info_left(billing_info_left), billing_info_right(billing_info_right),
        footer(footer), invoice_number(invoice_number), due_date(due_date)
    {}
    InvoiceTableEntry(const MessageTableEntry &messageTableEntry, const QString &company_info_left, const QString &company_info_right,
                      const QString &billing_info_left, const QString &billing_info_right, const QString &footer, const QString &invoice_number, const QDate &due_date):
        vchKey(messageTableEntry.vchKey), type(messageTableEntry.type), label(messageTableEntry.label), to_address(messageTableEntry.to_address), from_address(messageTableEntry.from_address),
        sent_datetime(messageTableEntry.sent_datetime), received_datetime(messageTableEntry.received_datetime),
        company_info_left(company_info_left), company_info_right(company_info_right), billing_info_left(billing_info_left), billing_info_right(billing_info_right),
        footer(footer), invoice_number(invoice_number), due_date(due_date)
    {}
};


/** Interface to Cinnicoin Secure Messaging Invoices from Qt view code. */
class InvoiceTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit InvoiceTableModel(MessageTablePriv *priv, QObject *parent = 0);
    ~InvoiceTableModel();

    enum ColumnIndex {
        Type = 0,   /**< Sent/Received */
        SentDateTime = 1, /**< Time Sent */
        ReceivedDateTime = 2, /**< Time Received */
        Label = 3,   /**< User specified label */
        ToAddress = 4, /**< To Bitcoin address */
        FromAddress = 5, /**< From Bitcoin address */
        InvoiceNumber = 6, /**< Plaintext */
        DueDate = 7, /**< Plaintext */
        //SubTotal = 8,           /**< SubTotal */
        Total = 8,           /**< Total */
        Paid = 9,             /**< Amount Paid */
        Outstanding = 10, /**< Amount Outstanding */
        // Hidden fields
        CompanyInfoLeft = 11, /**< Plaintext */
        CompanyInfoRight = 12, /**< Plaintext */
        BillingInfoLeft = 13, /**< Plaintext */
        BillingInfoRight = 14, /**< Plaintext */
        Footer = 15, /**< Plaintext */
    };

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

    MessageModel *getMessageModel();
    InvoiceItemTableModel *getInvoiceItemTableModel();

    void newInvoiceItem();

private:
    QStringList columns;
    MessageTablePriv *priv;
    InvoiceItemTableModel *invoiceItemTableModel;

public slots:
    friend class MessageTablePriv;

};


/** Interface to Cinnicoin Secure Messaging Invoice Items from Qt view code. */
class InvoiceItemTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit InvoiceItemTableModel(MessageTablePriv *priv, QObject *parent = 0);
    ~InvoiceItemTableModel();

    enum ColumnIndex {
        Code = 0,   /**< Item Code */
        Description = 1, /**< Item Description */
        Quantity = 2, /**< Item quantity */
        Price = 3,   /**< Item Price */
        //Tax = 4,   /**< Item Price */
        Amount = 4, /**< Total for row */
    };

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


private:
    QStringList columns;
    MessageTablePriv *priv;

public slots:
    friend class MessageTablePriv;
};

#endif // MESSAGEMODEL_H
