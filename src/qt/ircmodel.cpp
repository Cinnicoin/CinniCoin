#include "optionsmodel.h"
#include "ircmodel.h"
#include "guiconstants.h"

#include "alert.h"
#include "main.h"
#include "ui_interface.h"

#include <QSet>
#include <QTimer>

IRCModel::IRCModel(OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), optionsModel(optionsModel)
{
    /*
    // This timer will be fired repeatedly to check for messages
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollMessages()));
    pollTimer->start(MODEL_UPDATE_DELAY);
    */
    isConnected = false;
    subscribeToCoreSignals();
}

IRCModel::~IRCModel()
{
    unsubscribeFromCoreSignals();
}


void IRCModel::ircReceiveMessage(QString message)
{
    isConnected = true;

    emit ircMessageReceived(message);
}

OptionsModel *IRCModel::getOptionsModel()
{
    return optionsModel;
}

static void NotifyIRCMessage(IRCModel *ircmodel, std::string message)
{
    // Too noisy: OutputDebugStringF("NotifyIRCMessage %s\n", message);
    QMetaObject::invokeMethod(ircmodel, "ircReceiveMessage", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(message)));
}

void IRCModel::subscribeToCoreSignals()
{
    // Connect signals to irc
    uiInterface.NotifyIRCMessage.connect(boost::bind(NotifyIRCMessage, this, _1));
}

void IRCModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from irc
    uiInterface.NotifyIRCMessage.disconnect(boost::bind(NotifyIRCMessage, this, _1));
}
