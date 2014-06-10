// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CINNICOIN_EMESSAGE_H
#define CINNICOIN_EMESSAGE_H



#include "net.h"
#include "db.h"
#include "wallet.h"
#include "emessageclass.h"

const unsigned int SMSG_BUCKET_LEN = 60 * 10; // in seconds
const unsigned int SMSG_RETENTION  = 60 * 60 * 2; // in seconds

const unsigned int SMSG_TIME_LEEWAY = 30;


/** Inbox db changed.
 * @note called with lock cs_smsgInbox held.
 */
class SecInboxMsg;
extern boost::signals2::signal<void (SecInboxMsg& inboxHdr)> NotifySecMsgInboxChanged;

extern std::map<int64_t, SecMsgBucket> smsgSets;
extern CCriticalSection cs_smsg; // all except inbox and outbox
extern CCriticalSection cs_smsgInbox;
extern CCriticalSection cs_smsgOutbox;


// -- get at the data
class CBitcoinAddress_B : public CBitcoinAddress
{
public:
    unsigned char getVersion()
    {
        return nVersion;
    }
};

class CKeyID_B : public CKeyID
{
public:
    unsigned int* GetPPN()
    {
        return pn;
    }
};




// Could use CCrypter, duplicated to experiment with
class SMsgCrypter
{
private:
    unsigned char chKey[32];
    unsigned char chIV[16];
    bool fKeySet;
public:
    
    SMsgCrypter()
    {
        // Try to keep the key data out of swap (and be a bit over-careful to keep the IV that we don't even use out of swap)
        // Note that this does nothing about suspend-to-disk (which will put all our key data on disk)
        // Note as well that at no point in this program is any attempt made to prevent stealing of keys by reading the memory of the running process.
        LockedPageManager::instance.LockRange(&chKey[0], sizeof chKey);
        LockedPageManager::instance.LockRange(&chIV[0], sizeof chIV);
        fKeySet = false;
    }
    
    ~SMsgCrypter()
    {
        // clean key
        memset(&chKey, 0, sizeof chKey);
        memset(&chIV, 0, sizeof chIV);
        fKeySet = false;
        
        LockedPageManager::instance.UnlockRange(&chKey[0], sizeof chKey);
        LockedPageManager::instance.UnlockRange(&chIV[0], sizeof chIV);
    }
    
    bool SetKey(const std::vector<unsigned char>& vchNewKey, unsigned char* chNewIV);
    bool Encrypt(unsigned char* chPlaintext, uint32_t nPlain, std::vector<unsigned char> &vchCiphertext);
    bool Decrypt(unsigned char* chCiphertext, uint32_t nCipher, std::vector<unsigned char>& vchPlaintext);
};


class SecInboxMsg
{
public:
    int64_t                         timeReceived;
    std::string                     sAddrTo; // pointless not storing this, if someone sees message in local db, they already know it's to you.
    std::vector<unsigned char>      vchMessage;
    
    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->timeReceived);
        READWRITE(this->sAddrTo);
        READWRITE(this->vchMessage);
    )
        
};


class CSmesgInboxDB : public CDB
{
public:
    CSmesgInboxDB(const char* pszMode="r+") : CDB("smsgInbox.dat", pszMode) { }
    
    Dbc* GetAtCursor()
    {
        return GetCursor();
    }
    
    bool ReadUnread(std::vector<unsigned char>& vchUnread)
    {
        std::string skey = "Unread";
        return Read(skey, vchUnread);
    }
    
    bool WriteUnread(std::vector<unsigned char>& vchUnread)
    {
        std::string skey = "Unread";
        return Write(skey, vchUnread);
    }
    
    bool ReadSmesg(std::vector<unsigned char>& vchKey, SecInboxMsg& smsgib)
    {
        return Read(vchKey, smsgib);
    }
    
    bool WriteSmesg(std::vector<unsigned char>& vchKey, SecInboxMsg& smsgib)
    {
        return Write(vchKey, smsgib);
    }
    
    bool ExistsSmesg(std::vector<unsigned char>& vchKey)
    {
        return Exists(vchKey);
    }
    
    bool EraseSmesg(std::vector<unsigned char>& vchKey)
    {
        return Erase(vchKey);
    }
};

class CSmesgOutboxDB : public CDB
{
public:
    CSmesgOutboxDB(const char* pszMode="r+") : CDB("smsgOutbox.dat", pszMode) { }
    
    bool ReadPK(CKeyID& addr, CPubKey& pubkey)
    {
        return Read(addr, pubkey);
    }
    
    bool WritePK(CKeyID& addr, CPubKey& pubkey)
    {
        return Write(addr, pubkey);
    }
    
    bool ExistsPK(CKeyID& addr)
    {
        return Exists(addr);
    }
};

class CSmesgPubKeyDB : public CDB
{
public:
    CSmesgPubKeyDB(const char* pszMode="r+") : CDB("smsgPubKeys.dat", pszMode) { }
    
    bool ReadPK(CKeyID& addr, CPubKey& pubkey)
    {
        return Read(addr, pubkey);
    }
    
    bool WritePK(CKeyID& addr, CPubKey& pubkey)
    {
        return Write(addr, pubkey);
    }
    
    bool ExistsPK(CKeyID& addr)
    {
        return Exists(addr);
    }
};


std::string getTimeString(int64_t timestamp, char *buffer, size_t nBuffer);


bool SecureMsgStart(bool fScanChain);
bool SecureMsgStop();

bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv);

bool SecureMsgSendData(CNode* pto, bool fSendTrickle);


bool SecureMsgScanBlock(CBlock& block);
bool ScanChainForPublicKeys(CBlockIndex* pindexStart);
bool SecureMsgScanBlockChain();

int SecureMsgScanMessage(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload);

int GetStoredKey(CKeyID& ckid, CPubKey& cpkOut);

int GetLocalPublicKey(std::string& strAddress, std::string& strPublicKey);
int SecureMsgAddAddress(std::string& address, std::string& publicKey);

int SecureMsgRetrieve(SecMsgToken &token, std::vector<unsigned char>& vchData);

int SecureMsgReceive(std::vector<unsigned char>& vchData);

int SecureMsgStore(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, bool fUpdateBucket);
int SecureMsgStore(SecureMessage& smsg, bool fUpdateBucket);

int SecureMsgSend(std::string& addressFrom, std::string& addressTo, std::string& message);

int SecureMsgDecrypt(bool fTestOnly, std::string& address, unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, MessageData& msg);
int SecureMsgDecrypt(bool fTestOnly, std::string& address, SecureMessage& smsg, MessageData& msg);



#endif // CINNICOIN_EMESSAGE_H

