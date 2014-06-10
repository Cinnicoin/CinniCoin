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
    MessageTableEntry(const std::vector<unsigned char> vchKey, Type type, const QString &label, const QString &to_address, const QString &from_address, const QDateTime &sent_datetime, const QDateTime &received_datetime, const QString &message):
        vchKey(vchKey), type(type), label(label), to_address(to_address), from_address(from_address), sent_datetime(sent_datetime), received_datetime(received_datetime), message(message) {}
};

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
    MessageModel *parent;

    MessageTablePriv(MessageModel *parent):
        parent(parent) {}

    void refreshMessageTable()
    {
        cachedMessageTable.clear();

        std::vector<unsigned char> vchKey;
        {
            LOCK(cs_smsgInbox);

            CSmesgInboxDB dbInbox("cr+");

            char cbuf[256];

            Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                return;
                //throw runtime_error("Cannot get inbox DB cursor");

            uint32_t nMessages = 0;

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

            unsigned int fFlags = DB_NEXT; // same as using DB_FIRST for new cursor
            while (true)
            {
                int ret = pcursor->get(&datKey, &datValue, fFlags);

                if (ret == ENOMEM
                 || ret == DB_BUFFER_SMALL)
                {
                    if (datKey.get_size() > datKey.get_ulen())
                    {
                        vchKeyData.resize(datKey.get_size());
                        datKey.set_ulen(vchKeyData.size());
                        datKey.set_data(&vchKeyData[0]);
                    };

                    if (datValue.get_size() > datValue.get_ulen())
                    {
                        printf("Resizing vchValueData %d\n", datValue.get_size());
                        vchValueData.resize(datValue.get_size());
                        datValue.set_ulen(vchValueData.size());
                        datValue.set_data(&vchValueData[0]);
                    };
                    // try once more, when DB_BUFFER_SMALL cursor is not expected to move
                    ret = pcursor->get(&datKey, &datValue, fFlags);
                };

                if (ret == DB_NOTFOUND)
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s\n", ret, db_strerror(ret));
                    //throw runtime_error(cbuf);
                    return;
                };

                if (datKey.get_size() != 17)
                    continue; // not a message key

                nMessages++;
                // must be a better way?
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datKey.get_data(), datKey.get_size());
                ssValue >> vchKey;
                SecInboxMsg smsgInbox;
                ssValue.clear();
                ssValue.write((char*)datValue.get_data(), datValue.get_size());
                ssValue >> smsgInbox;

                MessageData msg;
                QString label;
                QDateTime sent_datetime;
                QDateTime received_datetime;

                //psmsg = &smsgInbox.vchMessage[0];
                uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {

                    label = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(smsgInbox.sAddrTo));

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
    }

    void newMessage(const SecInboxMsg & inboxHdr)
    {
        // we have to copy it, because it doesn't like constants going into Decrypt
        SecInboxMsg smsgInbox = inboxHdr;

        MessageData msg;
        QString label;
        QDateTime sent_datetime;
        QDateTime received_datetime;

        uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
        if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
        {
            label = parent->getWalletModel()->getAddressTableModel()->labelForAddress(QString::fromStdString(smsgInbox.sAddrTo));
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

    int size()
    {
        return cachedMessageTable.size();
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
    //QObject(parent), wallet(wallet), walletModel(walletModel)
    QAbstractTableModel(parent), wallet(wallet), walletModel(walletModel), priv(0)
{

    columns << tr("Type") << tr("Sent Date Time") << tr("Recieved Date Time") << tr("Label") << tr("To Address") << tr("From Address") << tr("Message");
    priv = new MessageTablePriv(this);
    priv->refreshMessageTable();

    // This timer will be fired repeatedly to check for messages
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollMessages()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

MessageModel::~MessageModel()
{
    delete priv;
    unsubscribeFromCoreSignals();
}

int MessageModel::getNumReceivedMessages() const
{
    int numMessages = 0;
    {
    }

    return numMessages;
}

int MessageModel::getNumSentMessages() const
{
    return 0;
    //return message->getNumUnreadMessages();
}

int MessageModel::getNumUnreadMessages() const
{
    return 0;
    //return message->getNumUnreadMessages();
}

void MessageModel::pollMessages()
{

}

bool MessageModel::getAddressOrPubkey(QString &address, QString &pubkey) const
{
    CBitcoinAddress addressParsed(address.toStdString());

    if(addressParsed.IsValid()) {
        CKeyID  destinationAddress;
        CPubKey destinationKey;

        addressParsed.GetKeyID(destinationAddress);

        if(GetStoredKey(destinationAddress, destinationKey) != 0)
            return false;

        address = destinationAddress.ToString().c_str();
        pubkey  = ValueString(destinationKey.Raw()).c_str();

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
        SecureMsgSend(addFrom, sendTo, message);

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


int MessageModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
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
            if(rec->label.isEmpty() && role == Qt::DisplayRole)
            {
                return tr("(no label)");
            }
            else
            {
                return rec->label;
            }
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
    else if (role == Qt::FontRole)
    {
        QFont font;
        if(index.column() == ToAddress || index.column() == FromAddress)
        {
            font = GUIUtil::bitcoinAddressFont();
        }
        return font;
    }
    else if (role == TypeRole)
    {
        switch(rec->type)
        {
        case MessageTableEntry::Sent:
            return Sent;
        case MessageTableEntry::Received:
            return Received;
        default: break;
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

void MessageModel::newMessage(const SecInboxMsg &smsgInbox)
{
    priv->newMessage(smsgInbox);
}

static void NotifySecMsgInbox(MessageModel *messageModel, SecInboxMsg inboxHdr)
{
    // Too noisy: OutputDebugStringF("NotifySecMsgInboxChanged %s\n", message);
    QMetaObject::invokeMethod(messageModel, "newMessage", Qt::QueuedConnection,
                              Q_ARG(SecInboxMsg, inboxHdr));
}

void MessageModel::subscribeToCoreSignals()
{
    qRegisterMetaType<SecInboxMsg>("SecInboxMsg");
    // Connect signals to irc
    NotifySecMsgInboxChanged.connect(boost::bind(NotifySecMsgInbox, this, _1));
}

void MessageModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from irc
    NotifySecMsgInboxChanged.disconnect(boost::bind(NotifySecMsgInbox, this, _1));
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

    } // LOCK(cs_smsgInbox);

    //priv->cachedMessageTable.removeOne(priv->cachedMessageTable.at(row));
    priv->parent->beginRemoveRows(parent, row, row);
    priv->cachedMessageTable.removeAt(row);
    priv->parent->endRemoveRows();

    return true;
}


