#include "sendmessagesentry.h"
#include "ui_sendmessagesentry.h"
#include "guiutil.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
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
    ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
    ui->sendTo->setPlaceholderText(tr("Enter a valid CinniCoin address"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->payTo);

    GUIUtil::setupAddressWidget(ui->payTo, this);
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
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->sendTo->setText(dlg.getReturnValue());
        ui->messageText->setFocus();
    }
}

void SendMessagesEntry::on_payTo_textChanged(const QString &address)
{
    if(!model)
        return;
    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
        ui->addAsLabel->setText(associatedLabel);
}

void SendMessagesEntry::setModel(WalletModel *model)
{
    this->model = model;

    if(model && model->getOptionsModel())
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
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
    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void SendMessagesEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

bool SendMessagesEntry::validate()
{
    // Check input validity
    bool retval = true;

    if(!ui->messageText->validate())
    {
        retval = false;
    }
    else
    {
        if(ui->messageText->text() == '')
        {
            // Cannot send a bkabj nessage
            ui->messageText->setValid(false);
            retval = false;
        }
    }

    if(!ui->sendTo->hasAcceptableInput() ||
       (model && !model->validateAddress(ui->sendTo->text())))
    {
        ui->sendTo->setValid(false);
        retval = false;
    }

    return retval;
}

SendCoinsRecipient SendMessagesEntry::getValue()
{
    SendCoinsRecipient rv;

    rv.address = ui->payTo->text();
    rv.label = ui->addAsLabel->text();
    rv.message = ui->payAmount->value();

    return rv;
}

QWidget *SendMessagesEntry::setupTabChain(QWidget *prev)
{
	QWidget::setTabOrder(prev, ui->payTo);
    QWidget::setTabOrder(ui->payTo, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    QWidget::setTabOrder(ui->deleteButton, ui->addAsLabel);

	return ui->payAmount->setupTabChain(ui->addAsLabel);
}

void SendMessagesEntry::setValue(const SendCoinsRecipient &value)
{
    ui->payTo->setText(value.address);
    ui->addAsLabel->setText(value.label);
    ui->payAmount->setValue(value.amount);
}

bool SendMessagesEntry::isClear()
{
    return ui->payTo->text().isEmpty();
}

void SendMessagesEntry::setFocus()
{
    ui->payTo->setFocus();
}

void SendMessagesEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmount with the current unit
        ui->payAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}
