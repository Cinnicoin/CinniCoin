#ifndef IRCMODEL_H
#define IRCMODEL_H

#include <QObject>
#include <vector>
#include "allocators.h" /* for SecureString */
#include <map>

class OptionsModel;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendIRCMessage
{
public:
    std::string message;
};

/** Interface to Cinnicoin Secure Messaging from Qt view code. */
class IRCModel : public QObject
{
    Q_OBJECT

public:
    explicit IRCModel(OptionsModel *optionsModel, QObject *parent = 0);
    ~IRCModel();

private:
    OptionsModel *optionsModel;
    //QTimer *pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

public slots:
    void ircReceiveMessage(QString message);
    /* Check for new messages */
    //void pollMessages();

signals:
    // Receive IRC Message
    void ircMessageReceived(QString message);
    //void NotifyIRCMessage();

    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};


#endif // IRCMODEL_H
