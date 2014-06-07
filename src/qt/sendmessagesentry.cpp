#include "sendmessagesentry.h"
#include "ui_sendmessagesentry.h"
#include "guiutil.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "messagemodel.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"

#include <QApplication>
#include <QClipboard>

SendMessagesEntry::SendMessagesEntry(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::SendMessagesEntry),
    model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->sendToLayout->setSpacing(4);
#endif
#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->publicKey->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
    ui->sendTo->setPlaceholderText(tr("Enter a valid CinniCoin address"));
    ui->addAsLabel->setPlaceholderText(tr("Enter the public key for the address above, it is not in the blockchain"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->sendTo);

    GUIUtil::setupAddressWidget(ui->sendTo, this);
}

SendMessagesEntry::~SendMessagesEntry()
{
    delete ui;
}

void SendMessagesEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->sendTo->setText(QApplication::clipboard()->text());
}

void SendMessagesEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;

    AddressBookPage dlg(AddressBookPage::ForSending, AddressBookPage::SendingTab, this);

    dlg.setModel(model->walletModel->getAddressTableModel());

    if(dlg.exec())
    {
        ui->sendTo->setText(dlg.getReturnValue());
        ui->messageText->setFocus();
    }
}

void SendMessagesEntry::on_sendTo_textChanged(const QString &address)
{
    if(!model)
        return;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = wallet->getAddressTableModel()->labelForAddress(address);

    if(!associatedLabel.isEmpty())
        ui->addAsLabel->setText(associatedLabel);
}

void SendMessagesEntry::setModel(MessageModel *model)
{

    this->model = model;

    if(model && model->walletModel && model->walletModel->getOptionsModel())
        connect(ui->messageText, SIGNAL(textChanged()), this, SIGNAL(messageTextChanged()));

    clear();
}

void SendMessagesEntry::setRemoveEnabled(bool enabled)
{
    ui->deleteButton->setEnabled(enabled);
}

void SendMessagesEntry::clear()
{
    ui->sendTo->clear();
    ui->addAsLabel->clear();
    ui->messageText->clear();
    ui->sendTo->setFocus();
}

void SendMessagesEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

bool SendMessagesEntry::validate()
{

    if(ui->messageText->toPlainText() == "")
    {
        // Cannot send a blank message
        //ui->messageText->setValid(false);
        return false;
    }

    if(!ui->sendTo->hasAcceptableInput() || (model->walletModel->validateAddress(ui->sendTo->text())))
    {
        //ui->sendTo->setValid(false);
        return false;
    }

    return true;
}

SendMessagesRecipient SendMessagesEntry::getValue()
{
    SendMessagesRecipient rv;

    rv.address = ui->sendTo->text();
    rv.label = ui->addAsLabel->text();
    rv.pubkey = ui->publicKey->text();
    rv.message = ui->messageText->toPlainText();

    return rv;
}


QWidget *SendMessagesEntry::setupTabChain(QWidget *prev)
{
    /*
    QWidget::setTabOrder(prev, ui->sendTo);
    QWidget::setTabOrder(ui->sendTo, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    QWidget::setTabOrder(ui->deleteButton, ui->addAsLabel);
    */

    //return ui->messageText->setupTabChain(ui->addAsLabel);
}

void SendMessagesEntry::setValue(const SendMessagesRecipient &value)
{
    ui->sendTo->setText(value.address);
    ui->addAsLabel->setText(value.label);
    ui->publicKey->setText(value.pubkey);
    ui->messageText->setPlainText(value.message);
}

bool SendMessagesEntry::isClear()
{
    return ui->sendTo->text().isEmpty();
}

void SendMessagesEntry::setFocus()
{
    ui->sendTo->setFocus();
}
