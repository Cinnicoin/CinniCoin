#include "guiutil.h"
#include "guiconstants.h"
#include "walletmodel.h"
#include "messagemodel.h"

#include "ui_interface.h"
#include "emessage.h"
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

    Type type;
    QString label;
    QString to_address;
    QString from_address;
    QDateTime sent_datetime;
    QDateTime received_datetime;
    QString message;

    MessageTableEntry() {}
    MessageTableEntry(Type type, const QString &label, const QString &to_address, const QString &from_address, const QDateTime &sent_datetime, const QDateTime &received_datetime, const QString &message):
        type(type), label(label), to_address(to_address), from_address(from_address), sent_datetime(sent_datetime), received_datetime(received_datetime), message(message) {}
};

struct MessageTableEntryLessThan
{
    bool operator()(const MessageTableEntry &a, const MessageTableEntry &b) const
    {
        return a.to_address < b.to_address;
    }
    bool operator()(const MessageTableEntry &a, const QString &b) const
    {
        return a.to_address < b;
    }
    bool operator()(const QString &a, const MessageTableEntry &b) const
    {
        return a < b.to_address;
    }
};

// Private implementation
class MessageTablePriv
{
public:
    CWallet *wallet;
    QList<MessageTableEntry> cachedMessageTable;
    MessageModel *parent;

    MessageTablePriv(CWallet *wallet, MessageModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshMessageTable()
    {
        cachedMessageTable.clear();

        std::vector<unsigned char> vchUnread;
        std::vector<unsigned char> vchKey;
        vchKey.resize(16);
        memset(&vchKey[0], 0, 16);

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
                ssValue.write((char*)datValue.get_data(), datValue.get_size());
                SecInboxMsg smsgInbox;
                ssValue >> smsgInbox;

                MessageData msg;
                const QString label = "";

                //psmsg = &smsgInbox.vchMessage[0];
                uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {
                    QDateTime sent_datetime;
                    QDateTime received_datetime;

                    sent_datetime    .setTime_t(msg.timestamp);
                    received_datetime.setTime_t(smsgInbox.timeReceived);

                    cachedMessageTable.append(
                        MessageTableEntry(MessageTableEntry::Received,
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

    columns << tr("Type") << tr("Label") << tr("To Address") << tr("From Address") << tr("Sent Date Time") << tr("Recieved Date Time") << tr("Message");
    priv = new MessageTablePriv(wallet, this);
    priv->refreshMessageTable();

    // This timer will be fired repeatedly to check for messages
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollMessages()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    //subscribeToCoreSignals();
}

MessageModel::~MessageModel()
{
    delete priv;
    //unsubscribeFromCoreSignals();
}

int MessageModel::getNumReceivedMessages() const
{
    int numMessages = 0;
    {
        //LOCK(message->cs_message);
        //numMessages = message->mapMessage.size();
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


/*
void MessageModel::updateMessage(const QString &hash, int status)
{
}
*/

MessageModel::SendMessagesReturn MessageModel::sendMessages(const QList<SendMessagesRecipient> &recipients, const QString &addressFrom)
{

    QSet<QString> setAddress;
    QString hex;

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
    }

    if(recipients.size() > setAddress.size())
        return DuplicateAddress;

    return SendMessagesReturn(OK, hex);
}

MessageModel::SendMessagesReturn MessageModel::sendMessages(const QList<SendMessagesRecipient> &recipients)
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
    MessageTableEntry *rec = static_cast<MessageTableEntry*>(index.internalPointer());

    Qt::ItemFlags retval = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
    // Can edit address and label for sending addresses,
    // and only label for receiving addresses.
    if(rec->type == MessageTableEntry::Sent ||
      (rec->type == MessageTableEntry::Received && index.column()==Label))
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

/*
void MessageModel::updateEntry(const QString &address, const QString &label, bool isMine, int status)
{
    // Update address book model from Bitcoin core
    priv->updateEntry(address, label, isMine, status);
}
*/
/*
QString AddressTableModel::addRow(const QString &type, const QString &label, const QString &address)
{
    std::string strLabel = label.toStdString();
    std::string strAddress = address.toStdString();

    editStatus = OK;

    if(type == Send)
    {
        if(!walletModel->validateAddress(address))
        {
            editStatus = INVALID_ADDRESS;
            return QString();
        }
        // Check for duplicate addresses
        {
            LOCK(wallet->cs_wallet);
            if(wallet->mapAddressBook.count(CBitcoinAddress(strAddress).Get()))
            {
                editStatus = DUPLICATE_ADDRESS;
                return QString();
            }
        }
    }
    else if(type == Receive)
    {
        // Generate a new address to associate with given label
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if(!ctx.isValid())
        {
            // Unlock wallet failed or was cancelled
            editStatus = WALLET_UNLOCK_FAILURE;
            return QString();
        }
        CPubKey newKey;
        if(!wallet->GetKeyFromPool(newKey, true))
        {
            editStatus = KEY_GENERATION_FAILURE;
            return QString();
        }
        strAddress = CBitcoinAddress(newKey.GetID()).ToString();
    }
    else
    {
        return QString();
    }
    // Add entry
    {
        LOCK(wallet->cs_wallet);
        wallet->SetAddressBookName(CBitcoinAddress(strAddress).Get(), strLabel);
    }
    return QString::fromStdString(strAddress);
}

bool AddressTableModel::removeRows(int row, int count, const QModelIndex & parent)
{
    Q_UNUSED(parent);
    AddressTableEntry *rec = priv->index(row);
    if(count != 1 || !rec || rec->type == AddressTableEntry::Receiving)
    {
        // Can only remove one row at a time, and cannot remove rows not in model.
        // Also refuse to remove receiving addresses.
        return false;
    }
    {
        LOCK(wallet->cs_wallet);
        wallet->DelAddressBookName(CBitcoinAddress(rec->address.toStdString()).Get());
    }
    return true;
}
*/
/* Look up label for address in address book, if not found return empty string.*/
/*
QString AddressTableModel::labelForAddress(const QString &address) const
{
    {
        LOCK(wallet->cs_wallet);
        CBitcoinAddress address_parsed(address.toStdString());
        std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(address_parsed.Get());
        if (mi != wallet->mapAddressBook.end())
        {
            return QString::fromStdString(mi->second);
        }
    }
    return QString();
}

int AddressTableModel::lookupAddress(const QString &address) const
{
    QModelIndexList lst = match(index(0, Address, QModelIndex()),
                                Qt::EditRole, address, 1, Qt::MatchExactly);
    if(lst.isEmpty())
    {
        return -1;
    }
    else
    {
        return lst.at(0).row();
    }
}

void AddressTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0, QModelIndex()), index(idx, columns.length()-1, QModelIndex()));
}


*/

