// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CINNICOIN_EMESSAGE_H
#define CINNICOIN_EMESSAGE_H


#include "net.h"
#include "wallet.h"
#include "db.h"
#include "emessageclass.h"

const int SMSG_BUCKET_LEN = 60 * 5; // in seconds
//const int SMSG_RETENTION  = 60 * 60 * 1; // in seconds
const int SMSG_RETENTION  = 60 * 30 * 1; // in seconds

extern std::map<int64_t, std::set<SecMsgToken> > smsgSets;


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
    
    bool SetKey(const std::vector<unsigned char>& chNewKey, unsigned char* chNewIV);
    bool Encrypt(unsigned char* chPlaintext, uint32_t nPlain, std::vector<unsigned char> &vchCiphertext);
    bool Decrypt(unsigned char* chCiphertext, uint32_t nCipher, std::vector<unsigned char>& vchPlaintext);
};




class CAddrToPubKeyDB : public CDB
{
public:
    CAddrToPubKeyDB(const char* pszMode="r+") : CDB("smsgPubKeys.dat", pszMode) { }
    
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




bool SecureMsgStart();
bool SecureMsgStop();

bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv);

bool SecureMsgSendData(CNode* pto, bool fSendTrickle);



bool ScanChainForPublicKeys(CBlockIndex* pindexStart);
bool SecureMsgScanBlockChain();

int SecureMsgScanMessages();

int GetStoredKey(CKeyID& ckid, CPubKey& cpkOut);

int SecureMsgAddAddress(std::string& address, std::string& publicKey);


int SecureMsgTransmit(CNode* pto, SecMsgToken &token);

int SecureMsgReceive(std::vector<unsigned char>& vchData);
int SecureMsgStore(SecureMessage& smsg);
int SecureMsgRetrieve(SecureMessage& smsg, long int offset);

int SecureMsgSend(std::string& addressFrom, std::string& addressTo, std::string& message);

int SecureMsgDecrypt(std::string& address, SecureMessage& smsg, MessageData& msg);



#endif // CINNICOIN_EMESSAGE_H

