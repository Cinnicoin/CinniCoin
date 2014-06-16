#include "guiutil.h"
#include "guiconstants.h"
#include "walletmodel.h"
#include "messagemodel.h"
#include "addresstablemodel.h"

#include "ui_interface.h"
#include "base58.h"

#include <QSet>
#include <QTimer>
#include <QDateTime>
#include <QSortFilterProxyModel>
#include <QClipboard>
#include <QMessageBox>
#include <QMenu>
#include <QFont>
#include <QColor>

const QString MessageModel::Sent = "Sent";
const QString MessageModel::Received = "Received";



struct MessageTableEntryLessThan
{
    bool operator()(const MessageTableEntry &a, const MessageTableEntry &b) const
    {
        return a.received_datetime < b.received_datetime;
    }
    bool operator()(const MessageTableEntry &a, const QDateTime &b) const
    {
        return a.received_datetime < b;
    }
    bool operator()(const QDateTime &a, const MessageTableEntry &b) const
    {
        return a < b.received_datetime;
    }
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

                    cachedMessageTable.append(
                        MessageTableEntry(vchKey,
                                          MessageTableEntry::Received,
                                          label,
                                          QString::fromStdString(smsgInbox.sAddrTo),
                                          QString::fromStdString(msg.sFromAddress),
                                          sent_datetime,
                                          received_datetime,
                                          QString((char*)&msg.vchMessage[0])));
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

                    cachedMessageTable.append(
                        MessageTableEntry(vchKey,
                                          MessageTableEntry::Sent,
                                          label,
                                          QString::fromStdString(smsgOutbox.sAddrTo),
                                          QString::fromStdString(msg.sFromAddress),
                                          sent_datetime,
                                          received_datetime,
                                          QString((char*)&msg.vchMessage[0])));
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

            // Find message in model
            QList<MessageTableEntry>::iterator lower = qLowerBound(
                cachedMessageTable.begin(), cachedMessageTable.end(), received_datetime, MessageTableEntryLessThan());
            int lowerIndex = (lower - cachedMessageTable.begin());

            std::vector<unsigned char> vchKey;

            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], &smsgInbox.vchMessage[0] + 5, 8); // timestamp
            memcpy(&vchKey[8], &smsgInbox.vchMessage[SMSG_HDR_LEN], 8);    // sample

            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedMessageTable.insert(lowerIndex, MessageTableEntry(vchKey,
                                                                    MessageTableEntry::Received,
                                                                    label,
                                                                    QString::fromStdString(smsgInbox.sAddrTo),
                                                                    QString::fromStdString(msg.sFromAddress),
                                                                    sent_datetime,
                                                                    received_datetime,
                                                                    QString((char*)&msg.vchMessage[0])));
            parent->endInsertRows();
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
            
            // Find message in model
            QList<MessageTableEntry>::iterator lower = qLowerBound(
                cachedMessageTable.begin(), cachedMessageTable.end(), received_datetime, MessageTableEntryLessThan());
            int lowerIndex = (lower - cachedMessageTable.begin());
            
            std::vector<unsigned char> vchKey;

            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], pHeader + 5, 8);  // timestamp
            memcpy(&vchKey[8], pPayload, 8);     // sample
            
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            
            cachedMessageTable.insert(lowerIndex, MessageTableEntry(vchKey,
                                      MessageTableEntry::Sent,
                                      labelTo,
                                      QString::fromStdString(smsgOutbox.sAddrTo),
                                      QString::fromStdString(msg.sFromAddress),
                                      sent_datetime,
                                      received_datetime,
                                      QString((char*)&msg.vchMessage[0])));
            parent->endInsertRows();
            
        };
    }

    MessageTableEntry *index(int idx)
    {
        if(idx >= 0 && idx < cachedMessageTable.size())
        {
            return &cachedMessageTable[idx];
        }
        else
        {
            return 0;
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
	    case Label:
	        return (rec->label.isEmpty() ? tr("(no label)") : rec->label);
	    case ToAddress:
	        return rec->to_address;

	    case FromAddress:
	        return rec->from_address;

	    case SentDateTime:
	        return rec->sent_datetime;

	    case ReceivedDateTime:
	        return rec->received_datetime;

	    case Message:
	        return rec->message;

	    case TypeInt:
	        return rec->type;
	    case Type:
	        switch(rec->type)
	        {
	        case MessageTableEntry::Sent:
	            return Sent;
	        case MessageTableEntry::Received:
	            return Received;
	        default: break;
	        }
	    }
    }

    return QVariant();
}

QVariant MessageModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags MessageModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can only label.
    if(index.column()==Label)
    {
        retval |= Qt::ItemIsEditable;
    }

    return retval;
}

QModelIndex MessageModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    MessageTableEntry *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

bool MessageModel::removeRows(int row, int count, const QModelIndex & parent)
{


    MessageTableEntry *rec = priv->index(row);
    if(count != 1 || !rec)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }

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
    columns << tr("Type") << tr("Sent Date Time") << tr("Recieved Date Time") << tr("Label") << tr("To Address") << tr("From Address") << tr("Invoice Number") << tr("Due Date") << "" << "" << "" << "" << "";

    invoiceItemTableModel = new InvoiceItemTableModel(priv, parent);
}

InvoiceTableModel::~InvoiceTableModel()
{

}

InvoiceItemTableModel *InvoiceTableModel::getInvoiceItemTableModel()
{
    return invoiceItemTableModel;
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

    InvoiceTableEntry *rec = static_cast<InvoiceTableEntry*>(index.internalPointer());

    switch(index.column())
    {
    case Label:
        return (rec->label.isEmpty() ? tr("(no label)") : rec->label);
    case ToAddress:
        return rec->to_address;

    case FromAddress:
        return rec->from_address;

    case SentDateTime:
        return rec->sent_datetime;

    case ReceivedDateTime:
        return rec->received_datetime;
    case CompanyInfoLeft:
        return rec->company_info_left;
    case CompanyInfoRight:
        return rec->company_info_right;
    case BillingInfoLeft:
        return rec->billing_info_left;
    case BillingInfoRight:
        return rec->billing_info_right;
    case InvoiceNumber:
        return rec->invoice_number;
    case DueDate:
        return rec->due_date;
    //case InvoiceItemTableEntry:
    //    return rec->item;
    case Type:
        switch(rec->type)
        {
        case InvoiceTableEntry::Sent:
            return MessageModel::Sent;
        case InvoiceTableEntry::Received:
            return MessageModel::Received;
        default: break;
        }
    }

    return QVariant();
}

QVariant InvoiceTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags InvoiceTableModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can only label.
    if(index.column()==Label)
    {
        retval |= Qt::ItemIsEditable;
    }

    return retval;
}

QModelIndex InvoiceTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    if(row >= 0 && row < priv->cachedInvoiceTable.size())
    {
        return createIndex(row, column, &priv->cachedInvoiceTable[row]);
    }
    else
    {
        return QModelIndex();
    }
}

bool InvoiceTableModel::removeRows(int row, int count, const QModelIndex & parent)
{


    if(count != 1 || !(row >= 0 && row < priv->cachedInvoiceTable.size()))
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }

    InvoiceTableEntry rec = priv->cachedInvoiceTable.at(row);

    if(rec.type == InvoiceTableEntry::Received)
    {

        LOCK(cs_smsgInbox);
        CSmesgInboxDB dbInbox("cr+");

        dbInbox.EraseSmesg(rec.vchKey);

    } else
    if(rec.type == InvoiceTableEntry::Sent)
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
    columns << tr("Code") << tr("Description") << tr("Quantity") << tr("Price") << tr("Tax") << tr("From Address") << tr("Message");

}

InvoiceItemTableModel::~InvoiceItemTableModel()
{

}


int InvoiceItemTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->cachedInvoiceItemTable.size();
    return 0;
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

    InvoiceItemTableEntry *rec = static_cast<InvoiceItemTableEntry*>(index.internalPointer());

    switch(index.column())
    {
    case Code:
         return rec->code;
    case Description:
        return rec->description;
    case Quantity:
        return rec->quantity;
    case Tax:
        return rec->tax;
    case Price:
        return rec->price;
    case Amount:
        return (rec->quantity * rec->price);
    }

    return QVariant();
}

QVariant InvoiceItemTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
    }
    return QVariant();
}

Qt::ItemFlags InvoiceItemTableModel::flags(const QModelIndex & index) const
{
    if(!index.isValid())
        return 0;

    return Qt::ItemIsSelectable | Qt::ItemIsEnabled | Qt::ItemIsEditable;
}

QModelIndex InvoiceItemTableModel::index(int row, int column, const QModelIndex & parent) const
{
    Q_UNUSED(parent);
    if(row >= 0 && row < priv->cachedInvoiceItemTable.size())
    {
        return createIndex(row, column, &priv->cachedInvoiceItemTable[row]);
    }
    else
    {
        return QModelIndex();
    }
}

bool InvoiceItemTableModel::removeRows(int row, int count, const QModelIndex & parent)
{

    if(count != 1 || !(row >= 0 && row < priv->cachedInvoiceItemTable.size()))
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }

    beginRemoveRows(parent, row, row);
    priv->cachedInvoiceItemTable.removeAt(row);
    endRemoveRows();

    return true;
}
