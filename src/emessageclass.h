// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CINNICOIN_EMESSAGE_CLASS_H
#define CINNICOIN_EMESSAGE_CLASS_H

// length of unencrypted header, 4 + 1 + 8 + 20 + 16 + 33 + 32 + 4 +4
const unsigned int SMSG_HDR_LEN = 122;

// length of encrypted header in payload
const unsigned int SMSG_PL_HDR_LEN = 1+20+65+4;


#pragma pack(push, 1)
class SecureMessage
{
public:
    SecureMessage()
    {
        nPayload = 0;
        pPayload = NULL;
    };
    
    ~SecureMessage()
    {
        if (pPayload)
            delete[] pPayload;
        pPayload = NULL;
    };
    
    unsigned char   hash[4];
    unsigned char   version;
    int64_t         timestamp;
    unsigned char   destHash[20];
    unsigned char   iv[16];
    unsigned char   cpkR[33];
    unsigned char   mac[32];
    unsigned char   nonse[4];
    uint32_t        nPayload;
    unsigned char*  pPayload;
        
};
#pragma pack(pop)


class MessageData
{
// -- Decrypted SecureMessage data
public:
    int64_t                     timestamp;
    std::string                 sToAddress;
    std::string                 sFromAddress;
    std::vector<unsigned char>  vchMessage;         // null terminated plaintext
};


class SecMsgToken
{
public:
    SecMsgToken(int64_t ts, unsigned char* p, int np, long int o)
    {
        timestamp = ts;
        
        if (np < 8) // payload will always be > 8, just make sure
            memset(sample, 0, 8);
        else
            memcpy(sample, p, 8);
        offset = o;
    };
    
    SecMsgToken() {};
    
    ~SecMsgToken() {};
    
    bool operator <(const SecMsgToken & y) const
    {
        // pack and memcmp from timesent?
        if (timestamp == y.timestamp)
            return memcmp(sample, y.sample, 8) < 0;
        return timestamp < y.timestamp;
    }
    
    int64_t                     timestamp;    // doesn't need to be full 64 bytes?
    unsigned char               sample[8];    // first 8 bytes of payload - a hash
    int64_t                     offset;       // offset
    
};


class SecMsgBucket
{
public:
    SecMsgBucket()
    {
        timeChanged     = 0;
        hash            = 0;
        nLockCount      = 0;
        nLockPeerId     = 0;
    };
    ~SecMsgBucket() {};
    
    void hashBucket();
    
    int64_t                     timeChanged;
    uint32_t                    hash;           // token set should get ordered the same on each node
    uint32_t                    nLockCount;     // set when smsgWant first sent, unset at end of smsgMsg, ticks down in ThreadSecureMsg()
    uint32_t                    nLockPeerId;    // id of peer that bucket is locked for
    std::set<SecMsgToken>       setTokens;
    
};


class SecMsgNode
{
// -- Tacked onto CNode
public:
    SecMsgNode()
    {
        lastSeen        = 0;
        lastMatched     = 0;
        ignoreUntil     = 0;
        nWakeCounter    = 0;
        nPeerId         = 0;
        fEnabled        = false;
    };
    
    ~SecMsgNode() {};
    
    int64_t                     lastSeen;
    int64_t                     lastMatched;
    int64_t                     ignoreUntil;
    uint32_t                    nWakeCounter;
    uint32_t                    nPeerId;
    bool                        fEnabled;
    
};

#endif // CINNICOIN_EMESSAGE_CLASS_H

