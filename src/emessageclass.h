// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CINNICOIN_EMESSAGE_CLASS_H
#define CINNICOIN_EMESSAGE_CLASS_H

// length of unencrypted header
// 4 + 1 + 8 + 20 + 16 + 33 + 32 + 4
const int SMSG_HDR_LEN = 118;

// length of encrypted header in payload
const int SMSG_PL_HDR_LEN = 1+20+65+4;


#pragma pack(1)
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
        //printf("~SecureMessage()\n");
        if (pPayload)
            delete[] pPayload;
        pPayload = NULL;
    };
    
    /*
    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->hash, 4);
    )
    */
    unsigned char   hash[4];
    unsigned char   version;
    int64_t         timestamp;
    unsigned char   destHash[20];
    unsigned char   iv[16];
    unsigned char   cpkR[33];
    unsigned char   mac[32];
    //std::vector<unsigned char> vchPayload;
    uint32_t        nPayload;
    unsigned char*  pPayload;
        
};
#pragma pack()

class MessageData
{
// Decrypted SecureMessage data
public:
    int64_t                     timestamp;
    std::vector<unsigned char>  vchToAddress;
    std::vector<unsigned char>  vchFromAddress;
    std::vector<unsigned char>  vchMessage; // null terminated
};

class SecMsgToken
{
public:
    SecMsgToken(int64_t ts, unsigned char* p, int np, long int o)
    {
        timestamp = ts;
        // payload will always be > 8, just make sure
        if (np < 8)
            memset(sample, 0, 8);
        else
            memcpy(sample, p, 8);
        offset = o;
    };
    
    SecMsgToken() {};
    
    ~SecMsgToken() {};
    
    //bool operator <(SecMsgToken const& x, SecMsgToken const& y)
    bool operator <(const SecMsgToken & y) const
    {
        // pack and memcmp from timesent?
        if (timestamp == y.timestamp)
            return memcmp(sample, y.sample, 8) < 0;
        return timestamp < y.timestamp;
    }
    
    int64_t                     timestamp;    // doesn't need to be full 64 bytes?
    unsigned char               sample[8];    // first 8 bytes of payload - a hash
    long int                    offset;       // offset
    
};


class SecMsgNode
{
// Tacked onto CNode
public:
    SecMsgNode()
    {
        lastSeen = 0;
        enabled  = false;
    };
    
    ~SecMsgNode() {};
    
    int64_t                     lastSeen;
    bool                        enabled;
    
};

#endif // CINNICOIN_EMESSAGE_CLASS_H
