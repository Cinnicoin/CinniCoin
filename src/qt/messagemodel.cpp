#include "messagemodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "walletmodel.h"

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



