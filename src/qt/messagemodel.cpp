#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "walletmodel.h"
#include "messagemodel.h"

#include "ui_interface.h"
#include "emessage.h"
#include "base58.h"

#include <QSet>
#include <QTimer>

MessageModel::MessageModel(CWallet * wallet, QObject *parent) :
    QObject(parent), wallet(wallet), walletModel(0)
{
    walletModel = new WalletModel(wallet, NULL);

    // This timer will be fired repeatedly to check for messages
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollMessages()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    //subscribeToCoreSignals();
}

MessageModel::~MessageModel()
{
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

/*
void MessageModel::updateMessage(const QString &hash, int status)
{
}
*/

MessageModel::SendMessagesReturn MessageModel::sendMessages(const QList<SendMessagesRecipient> &recipients)
{

    QSet<QString> setAddress;
    QString hex;

    if(recipients.empty())
        return OK;

    // Pre-check input data for validity
    foreach(const SendMessagesRecipient &rcp, recipients)
    {

        if(!walletModel->validateAddress(rcp.address))
        {
            return InvalidAddress;
        }

        setAddress.insert(rcp.address);

        if(rcp.message == "")
        {
            return MessageCreationFailed;
        }

    }

    if(recipients.size() > setAddress.size())
    {
        return DuplicateAddress;
    }

    return SendMessagesReturn(OK, hex);
}


>>>>>>> 27d7417ff5e19431a536b4175165e2c67db48966

#include "ui_interface.h"
#include "emessage.h"
#include "base58.h"

#include <QSet>
#include <QTimer>

MessageModel::MessageModel(CWallet * wallet, QObject *parent) :
    QObject(parent), wallet(wallet), walletModel(0)
{
    walletModel = new WalletModel(wallet, NULL, this);

    // This timer will be fired repeatedly to check for messages
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollMessages()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    //subscribeToCoreSignals();
}

MessageModel::~MessageModel()
{
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
