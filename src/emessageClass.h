// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef CINNICOIN_EMESSAGE_CLASS_H
#define CINNICOIN_EMESSAGE_CLASS_H

// length of unencrypted header
// 4 + 1 + 8 + 20 + 16 + 33 + 32 + 4
const int SMSG_HDR_LEN = 118;


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
    uint64_t        timestamp;
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
    uint64_t                    timestamp;
    std::vector<unsigned char>  vchToAddress;
    std::vector<unsigned char>  vchFromAddress;
    std::vector<unsigned char>  vchMessage; // null terminated
};


class SecMsgLocation
{
public:
    SecMsgLocation(){};
    SecMsgLocation(uint64_t ts, unsigned char* hsh, long int ofs)
    {
        timestamp = ts;
        //hash
        offset = ofs;
    };
    uint64_t                    timestamp;
    unsigned char               hash[4];
    long int                    offset;
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
    
    uint64_t                    lastSeen;
    bool                        enabled;
    
};


#endif // CINNICOIN_EMESSAGE_CLASS_H
