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

/** Interface to Cinnicoin Secure Messaging from Qt view code. */
class IRCModel : public QObject
{
    Q_OBJECT

public:
    explicit IRCModel(OptionsModel *optionsModel, QObject *parent = 0);
    ~IRCModel();

    OptionsModel *getOptionsModel();
    bool getIRCConnected() {return isConnected;}

private:
    OptionsModel *optionsModel;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();
    bool isConnected;

public slots:
    void ircReceiveMessage(QString message);

signals:
    // Receive IRC Message
    void ircMessageReceived(QString message);

    // Asynchronous error notification
    void error(const QString &title, const QString &message, bool modal);
};

#endif // IRCMODEL_H
