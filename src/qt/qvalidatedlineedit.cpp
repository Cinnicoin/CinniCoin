#include "qvalidatedlineedit.h"

#include "guiconstants.h"

QValidatedLineEdit::QValidatedLineEdit(QWidget *parent) :
    QLineEdit(parent), valid(true)
{
    connect(this, SIGNAL(textChanged(QString)), this, SLOT(markValid()));
}

void QValidatedLineEdit::setValid(bool valid)
{
    if(valid == this->valid)
    {
        return;
    }

    setStyleSheet(valid ? "" : STYLE_INVALID);

    this->valid = valid;
}

void QValidatedLineEdit::focusInEvent(QFocusEvent *evt)
{
    // Clear invalid flag on focus
    setValid(true);
    QLineEdit::focusInEvent(evt);
}

void QValidatedLineEdit::markValid()
{
    setValid(true);
}

void QValidatedLineEdit::clear()
{
    setValid(true);
    QLineEdit::clear();
}
