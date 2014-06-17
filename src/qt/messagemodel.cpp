#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoinunits.h"
#include "optionsmodel.h"
#include "walletmodel.h"
#include "messagemodel.h"
#include "addresstablemodel.h"

#include "ui_interface.h"
#include "base58.h"
#include "json_spirit.h"

#include <QSet>
#include <QTimer>
#include <QDateTime>
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QFont>
#include <QColor>

/// DEBUG #include <QDebug>

const QString MessageModel::Sent = "Sent";
const QString MessageModel::Received = "Received";

struct MessageTableEntryLessThan
{
    bool operator()(const MessageTableEntry &a, const MessageTableEntry &b) const {return a.received_datetime < b.received_datetime;};
    bool operator()(const MessageTableEntry &a, const QDateTime         &b) const {return a.received_datetime < b;}
    bool operator()(const QDateTime         &a, const MessageTableEntry &b) const {return a < b.received_datetime;}
};

struct InvoiceTableEntryLessThan
{
    bool operator()(const InvoiceTableEntry &a, const InvoiceTableEntry &b) const {return a.received_datetime < b.received_datetime;};
    bool operator()(const InvoiceTableEntry &a, const QDateTime         &b) const {return a.received_datetime < b;}
    bool operator()(const QDateTime         &a, const InvoiceTableEntry &b) const {return a < b.received_datetime;}
};

// Private implementation
class MessageTablePriv
{
public:
    QList<MessageTableEntry> cachedMessageTable;
    QList<InvoiceTableEntry> cachedInvoiceTable;
    QList<InvoiceItemTableEntry> cachedInvoiceItemTable;
    MessageModel *parent;

    MessageTablePriv(MessageModel *parent):
        parent(parent) {}

    void refreshMessageTable()
    {
        cachedMessageTable.clear();
        cachedInvoiceTable.clear();
        cachedInvoiceItemTable.clear();
        
        Dbt datKey;
        Dbt datValue;

        datKey.set_flags(DB_DBT_USERMEM);
        datValue.set_flags(DB_DBT_USERMEM);

        std::vector<unsigned char> vchKeyData;
        std::vector<unsigned char> vchValueData;

        vchKeyData.resize(100);
        vchValueData.resize(100);

        datKey.set_ulen(vchKeyData.size());
        datKey.set_data(&vchKeyData[0]);

        datValue.set_ulen(vchValueData.size());
        datValue.set_data(&vchValueData[0]);

        std::vector<unsigned char> vchKey;

        {
            LOCK(cs_smsgInbox);

            CSmesgInboxDB dbInbox("cr+");

            Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                return;
                //throw runtime_error("Cannot get inbox DB cursor");
                
            SecInboxMsg smsgInbox;
            unsigned int fFlags = DB_FIRST;

            while (dbInbox.NextSmesg(pcursor, fFlags, vchKey, smsgInbox))
            {
                fFlags = DB_NEXT;

                MessageData msg;
                QString label;
                QDateTime sent_datetime;
                QDateTime received_datetime;

                uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {

                    label = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(msg.sFromAddress));

                    sent_datetime    .setTime_t(msg.timestamp);
                    received_datetime.setTime_t(smsgInbox.timeReceived);

                    handleMessageEntry(MessageTableEntry(vchKey,
                                                         MessageTableEntry::Received,
                                                         label,
                                                         QString::fromStdString(smsgInbox.sAddrTo),
                                                         QString::fromStdString(msg.sFromAddress),
                                                         sent_datetime,
                                                         received_datetime,
                                                         QString((char*)&msg.vchMessage[0])),
                                       true);
                }
            };

            pcursor->close();
        }
        
        {
            LOCK(cs_smsgOutbox);

            CSmesgOutboxDB dbOutbox("cr+");

            Dbc* pcursor = dbOutbox.GetAtCursor();
            if (!pcursor)
                return;
                //throw runtime_error("Cannot get inbox DB cursor");
            
            SecOutboxMsg smsgOutbox;
            unsigned int fFlags = DB_FIRST;

            while (dbOutbox.NextSmesg(pcursor, fFlags, vchKey, smsgOutbox))
            {
                fFlags = DB_NEXT;

                MessageData msg;
                QString label;
                QDateTime sent_datetime;
                QDateTime received_datetime;

                uint32_t nPayload = smsgOutbox.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgOutbox.sAddrOutbox, &smsgOutbox.vchMessage[0], &smsgOutbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {

                    label = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(smsgOutbox.sAddrTo));

                    sent_datetime    .setTime_t(msg.timestamp);
                    received_datetime.setTime_t(msg.timestamp); // how to set to blank?

                    handleMessageEntry(MessageTableEntry(vchKey,
                                                         MessageTableEntry::Sent,
                                                         label,
                                                         QString::fromStdString(smsgOutbox.sAddrTo),
                                                         QString::fromStdString(msg.sFromAddress),
                                                         sent_datetime,
                                                         received_datetime,
                                                         QString((char*)&msg.vchMessage[0])),
                                       true);
                };
            };

            pcursor->close();
        }
    }

    void newMessage(const SecInboxMsg& inboxHdr)
    {
        // we have to copy it, because it doesn't like constants going into Decrypt
        //SecInboxMsg &smsgInbox = inboxHdr;
        SecInboxMsg &smsgInbox = const_cast<SecInboxMsg&>(inboxHdr); // un-const the reference

        MessageData msg;
        QString label;
        QDateTime sent_datetime;
        QDateTime received_datetime;

        uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
        if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
        {
            label = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(msg.sFromAddress));
            sent_datetime    .setTime_t(msg.timestamp);
            received_datetime.setTime_t(smsgInbox.timeReceived);

            std::vector<unsigned char> vchKey;

            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], &smsgInbox.vchMessage[0] + 5, 8); // timestamp
            memcpy(&vchKey[8], &smsgInbox.vchMessage[SMSG_HDR_LEN], 8);    // sample

            handleMessageEntry(MessageTableEntry(vchKey,
                                                 MessageTableEntry::Received,
                                                 label,
                                                 QString::fromStdString(smsgInbox.sAddrTo),
                                                 QString::fromStdString(msg.sFromAddress),
                                                 sent_datetime,
                                                 received_datetime,
                                                 QString((char*)&msg.vchMessage[0])),
                               false);
        }
    }

    void newOutboxMessage(const SecOutboxMsg& outboxHdr)
    {
        SecOutboxMsg &smsgOutbox = const_cast<SecOutboxMsg&>(outboxHdr); // un-const the reference

        MessageData msg;
        QString labelTo;
        QDateTime sent_datetime;
        QDateTime received_datetime;

        uint32_t nPayload = smsgOutbox.vchMessage.size() - SMSG_HDR_LEN;

        unsigned char* pHeader  = &smsgOutbox.vchMessage[0];
        unsigned char* pPayload = &smsgOutbox.vchMessage[SMSG_HDR_LEN];

        if (SecureMsgDecrypt(false, smsgOutbox.sAddrOutbox, pHeader, pPayload, nPayload, msg) == 0)
        {
            labelTo = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(smsgOutbox.sAddrTo));
            sent_datetime.setTime_t(msg.timestamp);
            received_datetime.setTime_t(msg.timestamp);

            std::vector<unsigned char> vchKey;

            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], pHeader + 5, 8);  // timestamp
            memcpy(&vchKey[8], pPayload, 8);     // sample

            handleMessageEntry(MessageTableEntry(vchKey,
                                                 MessageTableEntry::Sent,
                                                 labelTo,
                                                 QString::fromStdString(smsgOutbox.sAddrTo),
                                                 QString::fromStdString(msg.sFromAddress),
                                                 sent_datetime,
                                                 received_datetime,
                                                 QString((char*)&msg.vchMessage[0])),
                               false);
        };
    }

    void newInvoice(InvoiceTableEntry invoice)
    {
        addInvoiceEntry(invoice, false);
    }

    void newInvoiceItem()
    {
        InvoiceItemTableEntry invoice(true);
        addInvoiceItemEntry(invoice, false);
    }

    QString getInvoiceJSON(const int row)
    {
        QList<InvoiceTableEntry>::iterator inv;
        json_spirit::Object invoice;

        invoice.push_back(json_spirit::Pair("type", "invoice" ));
        invoice.push_back(json_spirit::Pair("company_info_left",  cachedInvoiceTable.at(row).company_info_left.toStdString()));
        invoice.push_back(json_spirit::Pair("company_info_right", cachedInvoiceTable[row].company_info_right.toStdString()));
        invoice.push_back(json_spirit::Pair("billing_info_left",  cachedInvoiceTable[row].billing_info_left.toStdString()));
        invoice.push_back(json_spirit::Pair("billing_info_right", cachedInvoiceTable[row].billing_info_right.toStdString()));
        invoice.push_back(json_spirit::Pair("footer",             cachedInvoiceTable[row].footer.toStdString()));
        invoice.push_back(json_spirit::Pair("invoice_number",     cachedInvoiceTable[row].invoice_number.toStdString()));
        invoice.push_back(json_spirit::Pair("due_date",           cachedInvoiceTable[row].due_date.toString().toStdString()));

        QList<InvoiceItemTableEntry>::iterator i;
        json_spirit::Array items;

        for (i = cachedInvoiceItemTable.begin(); i != cachedInvoiceItemTable.end(); ++i)
            if(i->vchKey == cachedInvoiceTable[row].vchKey)
            {
                json_spirit::Object item;

                item.push_back(json_spirit::Pair("code",         i->code.toStdString()));
                item.push_back(json_spirit::Pair("description",  i->description.toStdString()));
                item.push_back(json_spirit::Pair("price",        int64_t(i->price)));
                //item.push_back(json_spirit::Pair("tax",  i->tax));
                item.push_back(json_spirit::Pair("quantity",     i->quantity));

                items.push_back(item);
            }

        invoice.push_back(json_spirit::Pair("items", items));

        return QString::fromStdString(json_spirit::write(invoice));

    }

    MessageTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedMessageTable.size())
            return &cachedMessageTable[idx];
        else
            return 0;
    }

    int64 getTotal(std::vector<unsigned char> & vchKey) {
        int64 total = 0;

        QList<InvoiceItemTableEntry>::iterator i;

        for (i = cachedInvoiceItemTable.begin(); i != cachedInvoiceItemTable.end(); ++i)
            if(i->vchKey == vchKey)
                total += (i->price * i->quantity);

        return total;
    }

private:
    // Get the json value
    const json_spirit::mValue & find_value(json_spirit::mObject & obj, const char * key)
    {
        std::string newKey = key;

        json_spirit::mObject::const_iterator i = obj.find(newKey);

        if(i != obj.end() && i->first == newKey)
            return i->second;
        else
            return json_spirit::mValue::null;
    }

    const std::string get_value(json_spirit::mObject & obj, const char * key)
    {
        json_spirit::mValue val = find_value(obj, key);

        if(val.is_null())
            return "";
        else
            return val.get_str();
    }

    // Determine if it is a special message, i.e.: Invoice, Receipt, etc...
    void handleMessageEntry(const MessageTableEntry & message, const bool append)
    {
        json_spirit::mValue mVal;
        json_spirit::read(message.message.toStdString(), mVal);

        if(mVal.is_null())
        {
            addMessageEntry(message, append);
            return;
        }

        json_spirit::mObject mObj(mVal.get_obj());
        json_spirit::mValue mvType = find_value(mObj, "type");

        if(!mvType.is_null())
        {
            std::string type = mvType.get_str();

            if (type == "invoice")
            {
                json_spirit::mArray items(find_value(mObj, "items").get_array());

                for(uint i = 0;i < items.size();i++)
                {
                    json_spirit::mObject item_obj = items[i].get_obj();

                    addInvoiceItemEntry(InvoiceItemTableEntry(message.vchKey,
                                                              QString::fromStdString(get_value(item_obj,        "code")),
                                                              QString::fromStdString(get_value(item_obj, "description")),
                                                              find_value(item_obj, "quantity").get_int(),
                                                              find_value(item_obj,    "price").get_int64()),
                                                              //find_value(item_obj,      "tax").get_bool()),
                                        append);
                }

                addInvoiceEntry(InvoiceTableEntry(message,
                                                  QString::fromStdString(get_value(mObj, "company_info_left" )),
                                                  QString::fromStdString(get_value(mObj, "company_info_right")),
                                                  QString::fromStdString(get_value(mObj, "billing_info_left" )),
                                                  QString::fromStdString(get_value(mObj, "billing_info_right")),
                                                  QString::fromStdString(get_value(mObj, "footer"            )),
                                                  QString::fromStdString(get_value(mObj, "invoice_number"    )),
                                                  QDate::fromString(QString::fromStdString(get_value(mObj, "due_date")))),
                                append);

                // DEBUG std::string str = json_spirit::write(mVal);
                // DEBUG qDebug() << "invoice" << str.c_str();
            }
            else if (type == "receipt")
            {
                // DEBUG std::string str = json_spirit::write(mVal);
                // DEBUG qDebug() << "receipt" << str.c_str();
            }
            else
                addMessageEntry(message, append);
        }
        else
        {
            addMessageEntry(message, append);
            // DEBUG std::string str = json_spirit::write(mVal);
            // DEBUG qDebug() << "str" << str.c_str();
        }
    }

    void addMessageEntry(const MessageTableEntry & message, const bool & append)
    {
        if(append) cachedMessageTable.append(message);
        else
        {
            int index = qLowerBound(cachedMessageTable.begin(), cachedMessageTable.end(), message.received_datetime, MessageTableEntryLessThan()) - cachedMessageTable.begin();
            parent->beginInsertRows(QModelIndex(), index, index);
            cachedMessageTable.insert(
                        index,
                        message);
            parent->endInsertRows();
        }
    }

    void addInvoiceEntry(const InvoiceTableEntry & invoice, const bool append)
    {
        if(append) cachedInvoiceTable.append(invoice);
        else
        {
            int index = qLowerBound(cachedInvoiceTable.begin(), cachedInvoiceTable.end(), invoice.received_datetime, InvoiceTableEntryLessThan()) - cachedInvoiceTable.begin();
            parent->getInvoiceTableModel()->beginInsertRows(QModelIndex(), index, index);
            cachedInvoiceTable.insert(
                        index,
                        invoice);
            parent->getInvoiceTableModel()->endInsertRows();
        }
    }

    void addInvoiceItemEntry(const InvoiceItemTableEntry & item, const bool append)
    {
        if(append) cachedInvoiceItemTable.append(item);
        else
        {
            int index = cachedInvoiceItemTable.size();
            parent->getInvoiceTableModel()->getInvoiceItemTableModel()->beginInsertRows(QModelIndex(), index, index);
            cachedInvoiceItemTable.insert(index, item);
            parent->getInvoiceTableModel()->getInvoiceItemTableModel()->endInsertRows();
        }
    }

};

MessageModel::MessageModel(CWallet *wallet, WalletModel *walletModel, QObject *parent) :
    QAbstractTableModel(parent), wallet(wallet), walletModel(walletModel), optionsModel(0), priv(0), invoiceTableModel(0)
{
    columns << tr("Type") << tr("Sent Date Time") << tr("Recieved Date Time") << tr("Label") << tr("To Address") << tr("From Address") << tr("Message");

    optionsModel = walletModel->getOptionsModel();

    priv = new MessageTablePriv(this);
    priv->refreshMessageTable();
    invoiceTableModel = new InvoiceTableModel(priv, parent);

    subscribeToCoreSignals();
}

MessageModel::~MessageModel()
{
    delete priv;
    delete invoiceTableModel;
    unsubscribeFromCoreSignals();
}

bool MessageModel::getAddressOrPubkey(QString &address, QString &pubkey) const
{
    CBitcoinAddress addressParsed(address.toStdString());

    if(addressParsed.IsValid()) {
        CKeyID  destinationAddress;
        CPubKey destinationKey;

        addressParsed.GetKeyID(destinationAddress);

        if (SecureMsgGetStoredKey(destinationAddress, destinationKey) != 0
            && SecureMsgGetLocalKey(destinationAddress, destinationKey) != 0) // test if it's a local key
            return false;

        address = destinationAddress.ToString().c_str();
        pubkey = EncodeBase58(destinationKey.Raw()).c_str();

        return true;
    }

    return false;
}

WalletModel *MessageModel::getWalletModel()
{
    return walletModel;
}

OptionsModel *MessageModel::getOptionsModel()
{
    return optionsModel;
}

InvoiceTableModel *MessageModel::getInvoiceTableModel()
{
    return invoiceTableModel;
}

MessageModel::StatusCode MessageModel::sendMessages(const QList<SendMessagesRecipient> &recipients, const QString &addressFrom)
{

    QSet<QString> setAddress;

    if(recipients.empty())
        return OK;

    // Pre-check input data for validity
    foreach(const SendMessagesRecipient &rcp, recipients)
    {
        if(!walletModel->validateAddress(rcp.address))
            return InvalidAddress;

        if(rcp.message == "")
            return MessageCreationFailed;

        std::string sendTo  = rcp.address.toStdString();
        std::string pubkey  = rcp.pubkey.toStdString();
        std::string message = rcp.message.toStdString();
        std::string addFrom = addressFrom.toStdString();

        SecureMsgAddAddress(sendTo, pubkey);
        setAddress.insert(rcp.address);
        
        std::string sError;
        if (SecureMsgSend(addFrom, sendTo, message, sError) != 0)
        {
            QMessageBox::warning(NULL, tr("Send Secure Message"),
                tr("Send failed: %1.").arg(sError.c_str()),
                QMessageBox::Ok, QMessageBox::Ok);

            return InvalidAddress;
        };

        // Add addresses / update labels that we've sent to to the address book
        std::string strAddress = rcp.address.toStdString();
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(dest);

            // Check if we have a new address or an updated label
            if (mi == wallet->mapAddressBook.end() || mi->second != strLabel)
            {
                wallet->SetAddressBookName(dest, strLabel);
            }
        }
    }

    if(recipients.size() > setAddress.size())
        return DuplicateAddress;

    return OK;
}

MessageModel::StatusCode MessageModel::sendMessages(const QList<SendMessagesRecipient> &recipients)
{
    return sendMessages(recipients, "anon");
}

int MessageModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->cachedMessageTable.size();
}

int MessageModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant MessageModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    MessageTableEntry *rec = static_cast<MessageTableEntry*>(index.internalPointer());

    if(role == Qt::DisplayRole)
    {
	    switch(index.column())
	    {
            case Label:	           return (rec->label.isEmpty() ? tr("(no label)") : rec->label);
            case ToAddress:	       return rec->to_address;
            case FromAddress:      return rec->from_address;
            case SentDateTime:     return rec->sent_datetime;
            case ReceivedDateTime: return rec->received_datetime;
            case Message:          return rec->message;
            case TypeInt:          return rec->type;
            case Type:
                switch(rec->type)
                {
                    case MessageTableEntry::Sent:     return Sent;
                    case MessageTableEntry::Received: return Received;
                    default: break;
                }
	    }
    }

    return QVariant();
}

QVariant MessageModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return (orientation == Qt::Horizontal && role == Qt::DisplayRole ? columns[section] : QVariant());
}

Qt::ItemFlags MessageModel::flags(const QModelIndex & index) const
{
    if(index.isValid())
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled;

    return 0;
}

QModelIndex MessageModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    MessageTableEntry *data = priv->index(row);
    return (data ? createIndex(row, column, priv->index(row)) : QModelIndex());
}

bool MessageModel::removeRows(int row, int count, const QModelIndex & parent)
{
    MessageTableEntry *rec = priv->index(row);
    if(count != 1 || !rec)
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;

    if(rec->type == MessageTableEntry::Received)
    {
        LOCK(cs_smsgInbox);
        CSmesgInboxDB dbInbox("cr+");
        dbInbox.EraseSmesg(rec->vchKey);
    } else
    if(rec->type == MessageTableEntry::Sent)
    {
        LOCK(cs_smsgOutbox);
        CSmesgOutboxDB dbOutbox("cr+");
        dbOutbox.EraseSmesg(rec->vchKey);
    }

    beginRemoveRows(parent, row, row);
    priv->cachedMessageTable.removeAt(row);
    endRemoveRows();

    return true;
}

void MessageModel::newMessage(const SecInboxMsg &smsgInbox)
{
    priv->newMessage(smsgInbox);
}

void MessageModel::newOutboxMessage(const SecOutboxMsg &smsgOutbox)
{
    priv->newOutboxMessage(smsgOutbox);
}


static void NotifySecMsgInbox(MessageModel *messageModel, SecInboxMsg inboxHdr)
{
    // Too noisy: OutputDebugStringF("NotifySecMsgInboxChanged %s\n", message);
    QMetaObject::invokeMethod(messageModel, "newMessage", Qt::QueuedConnection,
                              Q_ARG(SecInboxMsg, inboxHdr));
}

static void NotifySecMsgOutbox(MessageModel *messageModel, SecOutboxMsg outboxHdr)
{
    QMetaObject::invokeMethod(messageModel, "newOutboxMessage", Qt::QueuedConnection,
                              Q_ARG(SecOutboxMsg, outboxHdr));
}

void MessageModel::subscribeToCoreSignals()
{
    qRegisterMetaType<SecInboxMsg>("SecInboxMsg");
    qRegisterMetaType<SecOutboxMsg>("SecOutboxMsg");

    // Connect signals
    NotifySecMsgInboxChanged.connect(boost::bind(NotifySecMsgInbox, this, _1));
    NotifySecMsgOutboxChanged.connect(boost::bind(NotifySecMsgOutbox, this, _1));
}

void MessageModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals
    NotifySecMsgInboxChanged.disconnect(boost::bind(NotifySecMsgInbox, this, _1));
    NotifySecMsgOutboxChanged.disconnect(boost::bind(NotifySecMsgOutbox, this, _1));
}



// InvoiceTableModel
InvoiceTableModel::InvoiceTableModel(MessageTablePriv *priv, QObject *parent) :
    QAbstractTableModel(parent), priv(priv), invoiceItemTableModel(0)
{
    columns << tr("Type") << tr("Sent Date Time") << tr("Recieved Date Time") << tr("Label") << tr("To Address") << tr("From Address") << tr("Invoice No.") << tr("Due Date") << "Invoice Amount" << "Amount Paid" << "Amount Outstanding";

    invoiceItemTableModel = new InvoiceItemTableModel(priv, parent);
}

InvoiceTableModel::~InvoiceTableModel()
{
    delete invoiceItemTableModel;
}

MessageModel *InvoiceTableModel::getMessageModel()
{
    return priv->parent;
}

InvoiceItemTableModel *InvoiceTableModel::getInvoiceItemTableModel()
{
    return invoiceItemTableModel;
}

void InvoiceTableModel::newInvoice(QString CompanyInfoLeft,
                                   QString CompanyInfoRight,
                                   QString BillingInfoLeft,
                                   QString BillingInfoRight,
                                   QString Footer,
                                   QDate   DueDate,
                                   QString InvoiceNumber)
{
    InvoiceTableEntry invoice(true);

    invoice.company_info_left  = CompanyInfoLeft;
    invoice.company_info_right = CompanyInfoRight;
    invoice.billing_info_left  = BillingInfoLeft;
    invoice.billing_info_right = BillingInfoRight;
    invoice.footer             = Footer;
    invoice.due_date           = DueDate;
    invoice.invoice_number     = InvoiceNumber;

    priv->newInvoice(invoice);
}

void InvoiceTableModel::newInvoiceItem()
{
    priv->newInvoiceItem();
}

QString InvoiceTableModel::getInvoiceJSON(const int row)
{
    return priv->getInvoiceJSON(row);
}

int InvoiceTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->cachedInvoiceTable.size();
}

int InvoiceTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant InvoiceTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    InvoiceTableEntry *rec;
    int64 total;

    if(role != Qt::TextAlignmentRole)
         rec = static_cast<InvoiceTableEntry*>(index.internalPointer());

    switch(role)
    {
        case Qt::DisplayRole:
            switch(index.column())
            {
                case Label:             return (rec->label.isEmpty() ? tr("(no label)") : rec->label);
                case ToAddress:         return rec->to_address;
                case FromAddress:       return rec->from_address;
                case SentDateTime:      return rec->sent_datetime;
                case ReceivedDateTime:  return rec->received_datetime;
                case CompanyInfoLeft:   return rec->company_info_left;
                case CompanyInfoRight:  return rec->company_info_right;
                case BillingInfoLeft:   return rec->billing_info_left;
                case BillingInfoRight:  return rec->billing_info_right;
                case Footer:            return rec->footer;
                case InvoiceNumber:     return rec->invoice_number;
                case DueDate:           return rec->due_date;
                case Paid:              return 0; // TODO: Calculate Paid
                case Outstanding:       return 0; // TODO: Calculate Outstanding
                case Type:
                    switch(rec->type)
                    {
                    case MessageTableEntry::Sent:     return MessageModel::Sent;
                    case MessageTableEntry::Received: return MessageModel::Received;
                    }

                case Total:
                    total = priv->getTotal(rec->vchKey);
                    return BitcoinUnits::formatWithUnit(priv->parent->getOptionsModel()->getDisplayUnit(), total);
                    break;
                default: break;
            }
            break;

        case Qt::TextAlignmentRole:
            switch(index.column())
            {
                case InvoiceNumber:
                case Total:
                case Paid:
                case Outstanding:
                    return Qt::AlignRight;
                default: break;
            }
            break;
        case Qt::UserRole:
            return QString((char*)&rec->vchKey[0]);
    }

    return QVariant();
}

/*
bool InvoiceTableModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    if(!index.isValid())
        return false;

    qDebug() << value << index;
    InvoiceTableEntry *rec = static_cast<InvoiceTableEntry*>(index.internalPointer());

    //editStatus = OK;

    if(role == Qt::EditRole)
    {
        qDebug() << value << index;

        switch(index.column())
        {
            case InvoiceNumber:    rec->invoice_number     = value.toString(); break;
            case DueDate:          rec->due_date           = value.toDate(); break;
            case CompanyInfoLeft:  rec->company_info_left  = value.toString(); break;
            case CompanyInfoRight: rec->company_info_right = value.toString(); break;
            case BillingInfoLeft:  rec->billing_info_left  = value.toString(); break;
            case BillingInfoRight: rec->billing_info_right = value.toString(); break;
            case Footer:           rec->footer             = value.toString(); break;
        }

        return true;
    }
    return false;
}

void InvoiceTableModel::setData(const int row, const int col, const QVariant & value)
{
    InvoiceTableEntry rec = priv->cachedInvoiceTable.at(row);

    qDebug() << value << col;

    switch(col)
    {
        case InvoiceNumber:    rec.invoice_number     = value.toString(); break;
        case DueDate:          rec.due_date           = value.toDate();   break;
        case CompanyInfoLeft:  rec.company_info_left  = value.toString(); break;
        case CompanyInfoRight: rec.company_info_right = value.toString(); break;
        case BillingInfoLeft:  rec.billing_info_left  = value.toString(); break;
        case BillingInfoRight: rec.billing_info_right = value.toString(); break;
        case Footer:           rec.footer             = value.toString(); break;
    }
}
*/

QVariant InvoiceTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return (orientation == Qt::Horizontal && role == Qt::DisplayRole ? columns[section] : QVariant());
}

Qt::ItemFlags InvoiceTableModel::flags(const QModelIndex & index) const
{
    if(index.isValid())
        return Qt::ItemIsSelectable | Qt::ItemIsEnabled;

    return 0;
}

QModelIndex InvoiceTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    return (row >= 0 && row < priv->cachedInvoiceTable.size() ? createIndex(row, column, &priv->cachedInvoiceTable[row]) : QModelIndex());
}

bool InvoiceTableModel::removeRows(int row, int count, const QModelIndex & parent)
{

    if(count != 1 || !(row >= 0 && row < priv->cachedInvoiceTable.size()))
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;

    InvoiceTableEntry rec = priv->cachedInvoiceTable.at(row);

    if(rec.type == MessageTableEntry::Received)
    {

        LOCK(cs_smsgInbox);
        CSmesgInboxDB dbInbox("cr+");

        dbInbox.EraseSmesg(rec.vchKey);

    } else
    if(rec.type == MessageTableEntry::Sent)
    {
        LOCK(cs_smsgOutbox);
        CSmesgOutboxDB dbOutbox("cr+");

        dbOutbox.EraseSmesg(rec.vchKey);
    }

    beginRemoveRows(parent, row, row);
    priv->cachedInvoiceTable.removeAt(row);
    endRemoveRows();

    return true;
}


// InvoiceItemTableModel
InvoiceItemTableModel::InvoiceItemTableModel(MessageTablePriv *priv, QObject *parent) :
    QAbstractTableModel(parent), priv(priv)
{
    columns << tr("Code") << tr("Description") << tr("Quantity") << tr("Price") /*<< tr("Tax")*/ << tr("Amount");

}

InvoiceItemTableModel::~InvoiceItemTableModel()
{

}

int InvoiceItemTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->cachedInvoiceItemTable.size();
}

int InvoiceItemTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant InvoiceItemTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();

    InvoiceItemTableEntry *rec;

    if(role != Qt::TextAlignmentRole)
         rec = static_cast<InvoiceItemTableEntry*>(index.internalPointer());

    switch(role)
    {
        case Qt::DisplayRole:
            switch(index.column())
            {
                case Code:
                     return rec->code;
                case Description:
                    return rec->description;
                case Quantity:
                    return rec->quantity;
                //case Tax:
                //    return rec->tax;
                case Price:
                    return BitcoinUnits::formatWithUnit(priv->parent->getOptionsModel()->getDisplayUnit(), rec->price);
                case Amount:
                    return BitcoinUnits::formatWithUnit(priv->parent->getOptionsModel()->getDisplayUnit(), (rec->quantity * rec->price));
            }
            break;

        case Qt::TextAlignmentRole:
            switch(index.column())
            {
                case Quantity:
                //case Tax:
                case Price:
                case Amount:
                    return Qt::AlignRight;
                default: break;
            }
            break;
        case Qt::UserRole:
            return QString((char*)&rec->vchKey[0]);
    }

    return QVariant();
}

bool InvoiceItemTableModel::setData(const QModelIndex & index, const QVariant & value, int role)
{
    if(!index.isValid())
        return false;

    InvoiceItemTableEntry *rec = static_cast<InvoiceItemTableEntry*>(index.internalPointer());

    //editStatus = OK;


    if(role == Qt::EditRole)
    {
        switch(index.column())
        {
            case Code:        rec->code        = value.toString(); break;
            case Description: rec->description = value.toString(); break;
            case Quantity:
                rec->quantity    = value.toInt();
                emitDataChanged(index.row());
                break;
            case Price:
                BitcoinUnits::parse(priv->parent->getOptionsModel()->getDisplayUnit(), value.toString(), &rec->price);
                emitDataChanged(index.row());
                break;
        }

        return true;
    }
    return false;
}

QVariant InvoiceItemTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    return (orientation == Qt::Horizontal && role == Qt::DisplayRole ? columns[section] : QVariant());
}

Qt::ItemFlags InvoiceItemTableModel::flags(const QModelIndex & index) const
{
    if(index.isValid())
    {
        Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;

        if(index.column() != Amount)
            retval |= Qt::ItemIsEditable;

        return retval;
    }

    return 0;
}

QModelIndex InvoiceItemTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    return (row >= 0 && row < priv->cachedInvoiceItemTable.size() ? createIndex(row, column, &priv->cachedInvoiceItemTable[row]) : QModelIndex());
}

bool InvoiceItemTableModel::removeRows(int row, int count, const QModelIndex & parent)
{

    if(count != 1 || !(row >= 0 && row < priv->cachedInvoiceItemTable.size()))
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;

    beginRemoveRows(parent, row, row);
    priv->cachedInvoiceItemTable.removeAt(row);
    endRemoveRows();

    return true;
}

void InvoiceItemTableModel::emitDataChanged(const int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}
