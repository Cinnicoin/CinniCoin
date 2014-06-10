// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
Notes:
    Running with -debug could leave to and from address hashes and public keys in the log.
    
    parameters:
        -nosmsg             Disable secure messaging (fNoSmsg)
        -debugsmsg          Show extra debug messages (fDebugSmsg)
        -smsgscanchain      Scan the block chain for public key addresses on startup
    
    
*/

#include "emessage.h"

#include <stdint.h>
#include <time.h>
#include <map>
#include <stdexcept>
#include <sstream>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <boost/lexical_cast.hpp>


#include "base58.h"
#include "db.h"
#include "init.h" // pwalletMain

#include "lz4/lz4.h"
#include "lz4/lz4.c"

#include "xxhash/xxhash.h"
#include "xxhash/xxhash.c"

// TODO: For buckets older than current, only need to store length and hash in memory

boost::signals2::signal<void (SecInboxMsg& inboxHdr)> NotifySecMsgInboxChanged;
boost::signals2::signal<void (SecOutboxMsg& outboxHdr)> NotifySecMsgOutboxChanged;

std::map<int64_t, SecMsgBucket> smsgSets;

CCriticalSection cs_smsg; // all except inbox and outbox

CCriticalSection cs_smsgInbox;
CCriticalSection cs_smsgOutbox;


namespace fs = boost::filesystem;

bool SMsgCrypter::SetKey(const std::vector<unsigned char>& vchNewKey, unsigned char* chNewIV)
{
    // -- for EVP_aes_256_cbc() key must be 256 bit, iv must be 128 bit.
    memcpy(&chKey[0], &vchNewKey[0], sizeof(chKey));
    memcpy(chIV, chNewIV, sizeof(chIV));
    
    fKeySet = true;
    
    return true;
};

bool SMsgCrypter::Encrypt(unsigned char* chPlaintext, uint32_t nPlain, std::vector<unsigned char> &vchCiphertext)
{
    if (!fKeySet)
        return false;
    
    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCK_SIZE - 1 bytes
    int nLen = nPlain;
    
    int nCLen = nLen + AES_BLOCK_SIZE, nFLen = 0;
    vchCiphertext = std::vector<unsigned char> (nCLen);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_EncryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    if (fOk) fOk = EVP_EncryptUpdate(&ctx, &vchCiphertext[0], &nCLen, chPlaintext, nLen);
    if (fOk) fOk = EVP_EncryptFinal_ex(&ctx, (&vchCiphertext[0])+nCLen, &nFLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk)
        return false;

    vchCiphertext.resize(nCLen + nFLen);
    
    return true;
};

bool SMsgCrypter::Decrypt(unsigned char* chCiphertext, uint32_t nCipher, std::vector<unsigned char>& vchPlaintext)
{
    if (!fKeySet)
        return false;
    
    // plaintext will always be equal to or lesser than length of ciphertext
    int nPLen = nCipher, nFLen = 0;
    
    vchPlaintext.resize(nCipher);

    EVP_CIPHER_CTX ctx;

    bool fOk = true;

    EVP_CIPHER_CTX_init(&ctx);
    if (fOk) fOk = EVP_DecryptInit_ex(&ctx, EVP_aes_256_cbc(), NULL, &chKey[0], &chIV[0]);
    if (fOk) fOk = EVP_DecryptUpdate(&ctx, &vchPlaintext[0], &nPLen, &chCiphertext[0], nCipher);
    if (fOk) fOk = EVP_DecryptFinal_ex(&ctx, (&vchPlaintext[0])+nPLen, &nFLen);
    EVP_CIPHER_CTX_cleanup(&ctx);

    if (!fOk)
        return false;
    
    vchPlaintext.resize(nPLen + nFLen);
    
    return true;
};

void SecMsgBucket::hashBucket()
{
    if (fDebugSmsg)
        printf("SecMsgBucket::hashBucket()\n");
    
    timeChanged = GetTime();
    
    //printf("setTokens.begin()->timestamp %ld\n", setTokens.begin()->timestamp);
    //printf("setTokens.rbegin()->timestamp %ld\n", setTokens.rbegin()->timestamp);
    
    std::set<SecMsgToken>::iterator it;
    
    void* state = XXH32_init(1);
    
    for (it = setTokens.begin(); it != setTokens.end(); ++it)
    {
        //printf("it->timestamp %ld\n", it->timestamp);
        XXH32_update(state, it->sample, 8);
    };
    
    hash = XXH32_digest(state);
    
    if (fDebugSmsg)
        printf("setTokens.size() %lu, hash %u\n", setTokens.size(), hash);
};

bool CSmesgInboxDB::NextSmesg(Dbc* pcursor, unsigned int fFlags, std::vector<unsigned char>& vchKey, SecInboxMsg& smsgInbox)
{
    datKey.set_flags(DB_DBT_USERMEM);
    datValue.set_flags(DB_DBT_USERMEM);
    
    
    datKey.set_ulen(vchKeyData.size());
    datKey.set_data(&vchKeyData[0]);

    datValue.set_ulen(vchValueData.size());
    datValue.set_data(&vchValueData[0]);
    
    while (true) // Must loop, as want to return only message keys
    {
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        //printf("inbox DB ret %d, %s\n", ret, db_strerror(ret));
        if (ret == ENOMEM
         || ret == DB_BUFFER_SMALL)
        {
            if (datKey.get_size() > datKey.get_ulen())
            {
                vchKeyData.resize(datKey.get_size());
                datKey.set_ulen(vchKeyData.size());
                datKey.set_data(&vchKeyData[0]);
            };

            if (datValue.get_size() > datValue.get_ulen())
            {
                //printf("Resizing vchValueData %d\n", datValue.get_size());
                vchValueData.resize(datValue.get_size());
                datValue.set_ulen(vchValueData.size());
                datValue.set_data(&vchValueData[0]);
            };
            // try once more, when DB_BUFFER_SMALL cursor is not expected to move
            ret = pcursor->get(&datKey, &datValue, fFlags);
        };

        if (ret == DB_NOTFOUND)
            return false;
        else
        if (datKey.get_data() == NULL || datValue.get_data() == NULL || ret != 0)
        {
            printf("CSmesgInboxDB::NextSmesg(), DB error %d, %s\n", ret, db_strerror(ret));
            return false;
        };

        if (datKey.get_size() != 17)
        {
            fFlags = DB_NEXT; // don't want to loop forever
            continue; // not a message key
        }
        // must be a better way?
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datKey.get_data(), datKey.get_size());
        ssValue >> vchKey;
        //SecOutboxMsg smsgOutbox;
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());
        ssValue >> smsgInbox;
        break;
    }
    
    return true;
};


bool CSmesgOutboxDB::NextSmesg(Dbc* pcursor, unsigned int fFlags, std::vector<unsigned char>& vchKey, SecOutboxMsg& smsgOutbox)
{
    datKey.set_flags(DB_DBT_USERMEM);
    datValue.set_flags(DB_DBT_USERMEM);
    
    
    datKey.set_ulen(vchKeyData.size());
    datKey.set_data(&vchKeyData[0]);

    datValue.set_ulen(vchValueData.size());
    datValue.set_data(&vchValueData[0]);
    
    while (true) // Must loop, as want to return only message keys
    {
        int ret = pcursor->get(&datKey, &datValue, fFlags);
        //printf("inbox DB ret %d, %s\n", ret, db_strerror(ret));
        if (ret == ENOMEM
         || ret == DB_BUFFER_SMALL)
        {
            if (datKey.get_size() > datKey.get_ulen())
            {
                vchKeyData.resize(datKey.get_size());
                datKey.set_ulen(vchKeyData.size());
                datKey.set_data(&vchKeyData[0]);
            };

            if (datValue.get_size() > datValue.get_ulen())
            {
                //printf("Resizing vchValueData %d\n", datValue.get_size());
                vchValueData.resize(datValue.get_size());
                datValue.set_ulen(vchValueData.size());
                datValue.set_data(&vchValueData[0]);
            };
            // try once more, when DB_BUFFER_SMALL cursor is not expected to move
            ret = pcursor->get(&datKey, &datValue, fFlags);
        };

        if (ret == DB_NOTFOUND)
            return false;
        else
        if (datKey.get_data() == NULL || datValue.get_data() == NULL || ret != 0)
        {
            printf("CSmesgOutboxDB::NextSmesg(), DB error %d, %s\n", ret, db_strerror(ret));
            return false;
        };

        if (datKey.get_size() != 17)
        {
            fFlags = DB_NEXT; // don't want to loop forever
            continue; // not a message key
        }
        // must be a better way?
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        ssValue.SetType(SER_DISK);
        ssValue.clear();
        ssValue.write((char*)datKey.get_data(), datKey.get_size());
        ssValue >> vchKey;
        //SecOutboxMsg smsgOutbox;
        ssValue.clear();
        ssValue.write((char*)datValue.get_data(), datValue.get_size());
        ssValue >> smsgOutbox;
        break;
    }
    
    return true;
};





void ThreadSecureMsg(void* parg)
{
    // Make this thread recognisable
    RenameThread("CinniCoin-smsg");
    
    int delay = 0;
    
    while (!fShutdown)
    {
        // shutdown thread waits 5 seconds, this should be less
        Sleep(1000); // milliseconds
        
        delay++;
        if (delay < 30) // check every 30 seconds
            continue;
        delay = 0;
        
        int64_t now = GetTime();
        
        if (fDebugSmsg)
            printf("SecureMsgThread %ld \n", now);
        
        int64_t cutoffTime = now - SMSG_RETENTION;
        
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgSets.begin();
            
            while (it != smsgSets.end())
            {
                //if (fDebugSmsg)
                //    printf("Checking bucket %ld, size %lu \n", it->first, it->second.setTokens.size());
                if (it->first < cutoffTime)
                {
                    
                    if (fDebugSmsg)
                        printf("Removing bucket %ld \n", it->first);
                    std::string fileName = boost::lexical_cast<std::string>(it->first) + "_01.dat";
                    fs::path fullPath = GetDataDir() / "smsgStore" / fileName;
                    if (fs::exists(fullPath))
                    {
                        try {
                            fs::remove(fullPath);
                        } catch (const fs::filesystem_error& ex)
                        {
                            printf("Error removing bucket file %s.\n", ex.what());
                        };
                    } else
                        printf("Path %s does not exist \n", fullPath.string().c_str());
                    
                    
                    smsgSets.erase(it++);
                } else
                    ++it;
            };
        }; // LOCK(cs_smsg);
    };
    
    printf("ThreadSecureMsg exited.\n");
};


std::string getTimeString(int64_t timestamp, char *buffer, size_t nBuffer)
{
    struct tm* dt;
    dt = localtime(&timestamp);
    strftime(buffer, nBuffer, "%Y-%m-%d %H:%M:%S %Z ", dt);
    return std::string(buffer); // Copies the null-terminated character sequence
};

std::string fsReadable(uint64_t nBytes)
{
    char buffer[128];
    if (nBytes >= 1024ll*1024ll*1024ll*1024ll)
        snprintf(buffer, sizeof(buffer), "%.2f TB", nBytes/1024.0/1024.0/1024.0/1024.0);
    else
    if (nBytes >= 1024*1024*1024)
        snprintf(buffer, sizeof(buffer), "%.2f GB", nBytes/1024.0/1024.0/1024.0);
    else
    if (nBytes >= 1024*1024)
        snprintf(buffer, sizeof(buffer), "%.2f MB", nBytes/1024.0/1024.0);
    else
    if (nBytes >= 1024)
        snprintf(buffer, sizeof(buffer), "%.2f KB", nBytes/1024.0);
    else
        snprintf(buffer, sizeof(buffer), "%lu bytes", nBytes);
    return std::string(buffer);
};


/** called from AppInit2() in init.cpp */
bool SecureMsgStart(bool fScanChain)
{
    if (fNoSmsg)
    {
        printf("Secure messaging not started.\n");
        return false;
    };
    
    printf("Secure messaging starting.\n");
    
    
    if (fScanChain)
    {
        SecureMsgScanBlockChain();
    };
    
    //printf("sizeof(long int) %d.\n", sizeof(long int));
    //printf("sizeof(int64_t) %d.\n", sizeof(int64_t));
    //printf("sizeof(size_t) %d.\n", sizeof(size_t));
    
    
    int64_t now = GetTime();
    
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    fs::directory_iterator itend;
    
    
    if (fs::exists(pathSmsgDir)
        && fs::is_directory(pathSmsgDir))
    {
        for( fs::directory_iterator itd(pathSmsgDir) ; itd != itend ; ++itd)
        {
            if (!fs::is_regular_file(itd->status()))
                continue;
            
            std::string fileType = (*itd).path().extension().string();
            
            if (fileType.compare(".dat") != 0)
                continue;
                
            std::string fileName = (*itd).path().filename().string();
            
            if (fDebugSmsg)
                printf("Processing file: %s.\n", fileName.c_str());
            
            // TODO files must be split if > 2GB
            // time_noFile.dat
            size_t sep = fileName.find_last_of("_");
            if (sep == std::string::npos)
                continue;
            
            std::string stime = fileName.substr(0, sep);
            
            int64_t fileTime = boost::lexical_cast<int64_t>(stime);
            
            //printf("fileTime %ld.\n", fileTime);
            
            if (fileTime < now - SMSG_RETENTION)
            {
                printf("Dropping message set %ld.\n", fileTime);
                fs::remove((*itd).path());
                continue;
            };
            
            SecureMessage smsg;
            std::set<SecMsgToken>& tokenSet = smsgSets[fileTime].setTokens;
            
            {
                LOCK(cs_smsg);
                FILE *fp;
                
                if (!(fp = fopen((*itd).path().string().c_str(), "r")))
                {
                    printf("Error opening file: %s\n", strerror(errno));
                    continue;
                };
                
                while (1)
                {
                    long int ofs = ftell(fp);
                    SecMsgToken token;
                    token.offset = ofs;
                    if (fread(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
                    {
                        printf("fread header failed: %s\n", strerror(errno));
                        printf("End of file?\n");
                        break;
                    };
                    token.timestamp = smsg.timestamp;
                    
                    if (smsg.nPayload < 8)
                        continue;
                    
                    if (fread(token.sample, sizeof(unsigned char), 8, fp) != 8)
                    {
                        printf("fread data failed: %s\n", strerror(errno));
                        break;
                    };
                    
                    if (fseek(fp, smsg.nPayload-8, SEEK_CUR) != 0)
                    {
                        printf("fseek, strerror: %s.\n", strerror(errno));
                        break;
                    };
                    
                    tokenSet.insert(token);
                };
                
                fclose(fp);
            };
            smsgSets[fileTime].hashBucket();
            
            if (fDebugSmsg)
                printf("e smsgSets[fileTime].size() %ld, %lu\n", fileTime, smsgSets[fileTime].setTokens.size());
            
            //printf("fileType %s.\n", fileType.c_str());
            //printf("(*itd).string().c_str() %s.\n", (*itd).path().filename().string().c_str());
        };
    };
    
    
    
    NewThread(ThreadSecureMsg, NULL);
    return true;
};

/** called from Shutdown() in init.cpp */
bool SecureMsgStop()
{
    if (fNoSmsg)
        return false;
    
    printf("Stopping secure messaging.\n");
    
    
    return true;
};


bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv)
{
    if (fDebugSmsg)
        printf("SecureMsgReceiveData() %s %s.\n", pfrom->addrName.c_str(), strCommand.c_str());
    
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    {
        // break up?
        LOCK(cs_smsg);
    
    //pto->PushMessage("smsgQuery", "enabled");
    if (strCommand == "smsgPong")
    {
        if (fDebugSmsg)
             printf("Peer replied, secure messaging enabled.\n");
        
        pfrom->smsgData.enabled = true;
    }
    if (strCommand == "smsgPing")
    {
        //printf("got smsgPing.\n");
        pfrom->PushMessage("smsgPong");
    } else
    if (strCommand == "smsgMatch")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        
        int64_t time;
        if (vchData.size() < 8)
        {
            printf("smsgMatch, not enough data %lu.\n", vchData.size());
            pfrom->Misbehaving(1);
            return false;
        };
        
        memcpy(&time, &vchData[0], 8);
        pfrom->smsgData.lastMatched = time;
        
        if (fDebugSmsg)
            printf("Peer buckets matched at %ld.\n", time);
        
    } else
    if (strCommand == "smsgMsg")
    {
        //printf("got smsgPing.\n");
        //pfrom->PushMessage("smsgPong");
        
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        
        if (fDebugSmsg)
            printf("smsgMsg vchData.size() %lu.\n", vchData.size());
        
        SecureMsgReceive(vchData);
    } else
    if (strCommand == "smsgInv")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        //printf("vchData.size() %lu.\n", vchData.size());
        //printf("2vRecv.size() %d.\n", vRecv.size());
        //unsigned char *pRecv = (unsigned char*) &(*vRecv.begin());
        
        if (vchData.size() < 4)
            return false;
        
        uint32_t nbuckets = smsgSets.size(); // uint16?
        uint32_t nmessage;
        memcpy(&nmessage, &vchData[0], 4);
        if (fDebugSmsg)
            printf("Remote node sent %d bucket headers, this has %d.\n", nmessage, nbuckets);
        
        
        // Check no of buckets:
        if (nmessage > (SMSG_RETENTION / SMSG_BUCKET_LEN) + 1) // +1 for some leeway
        {
            printf("Peer sent more bucket headers than possible %u, %u.\n", nmessage, (SMSG_RETENTION / SMSG_BUCKET_LEN));
            pfrom->Misbehaving(1);
            return false;
        };
        
        
        if (vchData.size() < 4 + nmessage*16)
        {
            printf("Remote node did not send enough data.\n");
            pfrom->Misbehaving(1);
            return false;
        };
        
        std::vector<unsigned char> vchDataOut;
        vchDataOut.reserve(4 + 8 * nmessage); // reserve max possible size
        vchDataOut.resize(4);
        uint32_t nShowBuckets = 0;
        int64_t now = GetTime();
        
        unsigned char *p = &vchData[4];
        for (uint32_t i = 0; i < nmessage; ++i)
        {
            int64_t time;
            uint32_t ncontent, hash;
            //uint32_t nMatch = 0;
            memcpy(&time, p, 8);
            memcpy(&ncontent, p+8, 4);
            memcpy(&hash, p+12, 4);
            
            p += 16;
            
            // Check time valid:
            if (time < now - SMSG_RETENTION)
            {
                if (fDebugSmsg)
                    printf("Not interested in peer bucket %ld, has expired.\n", time);
                pfrom->Misbehaving(1);
                continue;
            };
            if (time > now + SMSG_TIME_LEEWAY)
            {
                if (fDebugSmsg)
                    printf("Not interested in peer bucket %ld, in the future.\n", time);
                pfrom->Misbehaving(5);
                continue;
            };
            
            if (fDebugSmsg)
            {
                printf("peer bucket %ld %u %u.\n", time, ncontent, hash);
                printf("this bucket %lu %u.\n", smsgSets[time].setTokens.size(), smsgSets[time].hash);
            };
            
            // -- if this node has more than the peer node, peer node will pull from this
            //    if then peer node has more this node will pull fom peer
            if (smsgSets[time].setTokens.size() < ncontent
                || (smsgSets[time].setTokens.size() == ncontent && ncontent > 0
                    && smsgSets[time].hash != hash)) // if same amount in buckets check hash
            {
                if (fDebugSmsg)
                    printf("Requesting contents of bucket %ld.\n", time);
                
                uint32_t sz = vchDataOut.size();
                vchDataOut.resize(sz + 8);
                memcpy(&vchDataOut[sz], &time, 8);
                
                nShowBuckets++;
            };
        };
        
        // TODO: should include hash?
        memcpy(&vchDataOut[0], &nShowBuckets, 4);
        if (vchDataOut.size() > 4)
            pfrom->PushMessage("smsgShow", vchDataOut);
        else
        {
            // peer has no buckets we want, don't send until something changes
            // peer will still request buckets fom this node if needed (< ncontent)
            vchDataOut.resize(8);
            memcpy(&vchDataOut[0], &now, 8);
            pfrom->PushMessage("smsgMatch", vchDataOut);
        };
        
    } else
    if (strCommand == "smsgShow")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        
        if (vchData.size() < 4)
            return false;
        
        uint32_t nBuckets;
        memcpy(&nBuckets, &vchData[0], 4);
        
        if (vchData.size() < 4 + nBuckets * 8)
            return false;
        
        if (fDebugSmsg)
            printf("smsgShow: peer wants %u buckets.\n", nBuckets);
        
        std::map<int64_t, SecMsgBucket>::iterator itb;
        std::set<SecMsgToken>::iterator it;
        
        std::vector<unsigned char> vchDataOut;
        int64_t time;
        unsigned char* pIn = &vchData[4];
        for (uint32_t i = 0; i < nBuckets; ++i, pIn += 8)
        {
            memcpy(&time, pIn, 8);
            
            // check time valid first?
            
            itb = smsgSets.find(time);
            if (itb == smsgSets.end())
            {
                if (fDebugSmsg)
                    printf("Don't have bucket %ld.\n", time);
                continue;
            };
            
            std::set<SecMsgToken>& tokenSet = (*itb).second.setTokens;
            
            vchDataOut.resize(8 + 16 * tokenSet.size());
            memcpy(&vchDataOut[0], &time, 8);
            
            unsigned char* p = &vchDataOut[8];
            for (it = tokenSet.begin(); it != tokenSet.end(); ++it)
            {
                //uint32_t size = it->second.size();
                memcpy(p, &it->timestamp, 8);
                memcpy(p+8, &it->sample, 8);
                
                p += 16;
            };
            pfrom->PushMessage("smsgHave", vchDataOut);
        };
        
        
    } else
    if (strCommand == "smsgHave")
    {
        // -- peer has these messages in bucket
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        
        if (vchData.size() < 8)
            return false;
        
        int n = (vchData.size() - 8) / 16;
        
        int64_t time;
        memcpy(&time, &vchData[0], 8);
        
        // Check time valid:
        if (time < GetTime() - SMSG_RETENTION)
        {
            if (fDebugSmsg)
                printf("Not interested in peer bucket %ld, has expired.\n", time);
            return false;
        };
        
        
        std::vector<unsigned char> vchDataOut;
        vchDataOut.resize(8);
        memcpy(&vchDataOut[0], &vchData[0], 8);
        
        std::set<SecMsgToken>& tokenSet = smsgSets[time].setTokens;
        std::set<SecMsgToken>::iterator it;
        SecMsgToken token;
        unsigned char* p = &vchData[8];
        
        for (int i = 0; i < n; ++i)
        {
            memcpy(&token.timestamp, p, 8);
            memcpy(&token.sample, p+8, 8);
            
            it = tokenSet.find(token);
            if (it == tokenSet.end())
            {
                int nd = vchDataOut.size();
                vchDataOut.resize(nd + 16);
                memcpy(&vchDataOut[nd], p, 16);
            };
            
            p += 16;
        };
        
        if (vchDataOut.size() > 8)
            pfrom->PushMessage("smsgWant", vchDataOut);
    } else
    if (strCommand == "smsgWant")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        
        if (vchData.size() < 8)
            return false;
        
        std::vector<unsigned char> vchOne;
        std::vector<unsigned char> vchBunch;
        
        vchBunch.resize(4+8); // nmessages + bucketTime
        
        int n = (vchData.size() - 8) / 16;
        
        int64_t time;
        uint32_t nBunch = 0;
        memcpy(&time, &vchData[0], 8);
        // todo check time valid
        
        std::map<int64_t, SecMsgBucket>::iterator itb;
        itb = smsgSets.find(time);
        if (itb == smsgSets.end())
        {
            if (fDebugSmsg)
                printf("Don't have bucket %ld.\n", time);
            return false;
        };
        
        std::set<SecMsgToken>& tokenSet = itb->second.setTokens;
        //std::set<SecMsgToken>& tokenSet = smsgSets[time].setTokens;
        std::set<SecMsgToken>::iterator it;
        SecMsgToken token;
        unsigned char* p = &vchData[8];
        for (int i = 0; i < n; ++i)
        {
            memcpy(&token.timestamp, p, 8);
            memcpy(&token.sample, p+8, 8);
            
            it = tokenSet.find(token);
            if (it == tokenSet.end())
            {
                if (fDebugSmsg)
                    printf("Don't have wanted message %ld.\n", token.timestamp);
            } else
            {
                //printf("Have message at %ld.\n", it->offset);
                token.offset = it->offset;
                //SecureMsgTransmit(pfrom, token);
                
                
                // -- put in vchOne so if SecureMsgRetrieve fails it won't corrupt vchBunch
                if (SecureMsgRetrieve(token, vchOne) == 0)
                {
                    nBunch++;
                    vchBunch.insert(vchBunch.end(), vchOne.begin(), vchOne.end()); // append
                } else
                {
                    printf("SecureMsgRetrieve failed %ld.\n", token.timestamp);
                }
                
                if (nBunch >= 500
                    || vchBunch.size() >= 96000)
                {
                    if (fDebugSmsg)
                        printf("Break bunch %u, %lu.\n", nBunch, vchBunch.size());
                    break; // end here, peer will send more want messages if needed.
                };
            };
            p += 16;
        };
        
        if (nBunch > 0)
        {
            if (fDebugSmsg)
                printf("Sending block of %u messages for bucket %ld.\n", nBunch, time);
            
            memcpy(&vchBunch[0], &nBunch, 4);
            memcpy(&vchBunch[4], &time, 8);
            pfrom->PushMessage("smsgMsg", vchBunch);
        };
    } else
    {
        // Unknown message
    };
    
    }; //  LOCK(cs_smsg);
    
    return true;
};

bool SecureMsgSendData(CNode* pto, bool fSendTrickle)
{
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    //printf("SecureMsgSendData() %s.\n", pto->addrName.c_str());
    
    
    int64_t now = time(NULL);
    
    if (pto->smsgData.lastSeen == 0)
    {
        // -- first contact
        if (fDebugSmsg)
            printf("SecureMsgSendData() new node %s.\n", pto->addrName.c_str());
        // -- Send smsgPing once, do nothing until receive 1st smsgPong (then set enabled)
        pto->PushMessage("smsgPing");
        pto->smsgData.lastSeen = time(NULL);
        return true;
    } else
    if (!pto->smsgData.enabled
        || now - pto->smsgData.lastSeen < 15)
    {
        return true;
    };
    
    
    //pto->PushMessage("smsgPing");
    
    {
        LOCK(cs_smsg);
        std::map<int64_t, SecMsgBucket>::iterator it;
        
        uint32_t nbuckets = smsgSets.size();
        if (nbuckets > 0) // no need to send keep alive pkts, coin messages already do that
        {
            std::vector<unsigned char> vchData;
            // TODO: should reserve?
            vchData.reserve(4 + nbuckets*16); // timestamp + size + hash
            
            uint32_t nbucketsShown = 0;
            vchData.resize(4);
            
            unsigned char* p = &vchData[4];
            for (it = smsgSets.begin(); it != smsgSets.end(); ++it)
            {
                SecMsgBucket &bkt = it->second;
                
                if (bkt.timeChanged < pto->smsgData.lastMatched)
                    continue; // peer has this bucket
                
                uint32_t size = bkt.setTokens.size();
                uint32_t hash = bkt.hash;
                
                vchData.resize(vchData.size() + 16);
                memcpy(p, &it->first, 8);
                memcpy(p+8, &size, 4);
                memcpy(p+12, &hash, 4);
                
                p += 16;
                nbucketsShown++;
                //if (fDebug)
                //    printf("Sending bucket %ld, size %d \n", it->first, it->second.size());
            };
            
            if (vchData.size() > 4)
            {
                memcpy(&vchData[0], &nbucketsShown, 4);
                if (fDebugSmsg)
                    printf("Sending %d bucket headers.\n", nbucketsShown);
                
                pto->PushMessage("smsgInv", vchData);
            };
        };
    }
    
    pto->smsgData.lastSeen = time(NULL);
    
    return true;
};


static int SecureMsgInsertAddress(CKeyID& hashKey, CPubKey& pubKey, CSmesgPubKeyDB& addrpkdb)
{
    /* insert key hash and public key to addressdb
        
        should have LOCK(cs_smsg) where db is opened
        
        returns
            0 success
            4 address is already in db
            5 error
    */
    
    
    if (addrpkdb.ExistsPK(hashKey))
    {
        //printf("DB already contains public key for address: %s.\n", coinAddress.ToString().c_str());
        //printf("DB already contains public key for address.\n");
        CPubKey cpkCheck;
        if (!addrpkdb.ReadPK(hashKey, cpkCheck))
        {
            printf("addrpkdb.Read failed.\n");
        } else
        {
            //printf("cpkCheck: %s.\n", ValueString(cpkCheck.Raw()).c_str());
            //printf("pubKey: %s.\n", ValueString(pubKey.Raw()).c_str());
            if (cpkCheck != pubKey)
                printf("DB already contains existing public key that does not match .\n");
        };
        return 4;
    };
    
    if (!addrpkdb.WritePK(hashKey, pubKey))
    {
        printf("Write pair failed.\n");
        return 5;
    };
    
    return 0;
};

int SecureMsgInsertAddress(CKeyID& hashKey, CPubKey& pubKey)
{
    int rv;
    {
        LOCK(cs_smsg);
        CSmesgPubKeyDB addrpkdb("cr+");
        
        rv = SecureMsgInsertAddress(hashKey, pubKey, addrpkdb);
    }
    return rv;
};


static bool ScanBlock(CBlock& block, CTxDB& txdb, CSmesgPubKeyDB& addrpkdb,
    uint32_t& nTransactions, uint32_t& nInputs, uint32_t& nPubkeys, uint32_t& nDuplicates)
{
    // should have LOCK(cs_smsg) where db is opened
    BOOST_FOREACH(CTransaction& tx, block.vtx)
    {
        if (!tx.IsStandard())
            continue; // leave out coinbase and others
        
        /*
        Look at the inputs of every tx.
        If the inputs are standard, get the pubkey from scriptsig and
        look for the corresponding output (the input(output of other tx) to the input of this tx)
        get the address from scriptPubKey
        add to db if address is unique.
        
        Would make more sense to do this the other way around, get address first for early out.
        
        */
        
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            CScript *script = &tx.vin[i].scriptSig;
            //printf("script %s.\n", script->ToString().c_str());
            
            opcodetype opcode;
            valtype vch;
            CScript::const_iterator pc = script->begin();
            CScript::const_iterator pend = script->end();
            
            uint256 prevoutHash;
            CKey key;
            
            // -- matching address is in scriptPubKey of previous tx output
            while (pc < pend)
            {
                if (!script->GetOp(pc, opcode, vch))
                    break;
                // -- opcode is the length of the following data, compressed public key is always 33
                if (opcode == 33)
                {
                    //printf("Found Compressed public key %s.\n", ValueString(vch).c_str());
                    
                    key.SetPubKey(vch);
                    
                    key.SetCompressedPubKey(); // ensure key is compressed
                    CPubKey pubKey = key.GetPubKey();
                    //printf("compressed public key %s.\n", ValueString(pubKey.Raw()).c_str());
                    
                    if (!pubKey.IsValid()
                        || !pubKey.IsCompressed())
                    {
                        printf("Public key is invalid %s.\n", ValueString(pubKey.Raw()).c_str());
                        continue;
                    };
                    
                    prevoutHash = tx.vin[i].prevout.hash;
                    CTransaction txOfPrevOutput;
                    if (!txdb.ReadDiskTx(prevoutHash, txOfPrevOutput))
                    {
                        printf("Could not get transaction for hash: %s.\n", prevoutHash.ToString().c_str());
                        continue;
                    };
                    
                    unsigned int nOut = tx.vin[i].prevout.n;
                    if (nOut >= txOfPrevOutput.vout.size())
                    {
                        printf("Output %u, not in transaction: %s.\n", nOut, prevoutHash.ToString().c_str());
                        //printf("txOfPrevOutput.vout.size() %u.\n", txOfPrevOutput.vout.size());
                        continue;
                    };
                    
                    CTxOut *txOut = &txOfPrevOutput.vout[nOut];
                    
                    CTxDestination addressRet;
                    if (!ExtractDestination(txOut->scriptPubKey, addressRet))
                    {
                        printf("ExtractDestination failed: %s.\n", prevoutHash.ToString().c_str());
                        break;
                    };
                    
                    
                    CBitcoinAddress coinAddress(addressRet);
                    //printf("coinAddress: %s.\n", coinAddress.ToString().c_str());
                    
                    // Can't serialise CBitcoinAddress, could go straight from CTxDestination
                    CKeyID hashKey;
                    if (!coinAddress.GetKeyID(hashKey))
                    {
                        printf("coinAddress.GetKeyID failed: %s.\n", coinAddress.ToString().c_str());
                        break;
                    };
                    
                    int rv = SecureMsgInsertAddress(hashKey, pubKey, addrpkdb);
                    if (rv != 0)
                    {
                        if (rv == 4)
                            nDuplicates++;
                        break;
                    };
                    nPubkeys++;
                    break;
                };
                
                //printf("opcode %d, %s, value %s.\n", opcode, GetOpName(opcode), ValueString(vch).c_str());
            };
            nInputs++;
        };
        nTransactions++;
        
        if (nTransactions % 10000 == 0) // for ScanChainForPublicKeys
        {
            printf("Scanning transaction no. %u.\n", nTransactions);
        };
    };
    return true;
};


bool SecureMsgScanBlock(CBlock& block)
{
    /*
    scan block for public key addresses
    called from ProcessMessage() in main where strCommand == "block"
    */
    
    if (fDebugSmsg)
        printf("SecureMsgScanBlock().\n");
    
    uint32_t nTransactions = 0;
    uint32_t nInputs = 0;
    uint32_t nPubkeys = 0;
    uint32_t nDuplicates = 0;
    
    {
        LOCK(cs_smsg);
        
        CSmesgPubKeyDB addrpkdb("cw");
        CTxDB txdb("r");
        
        
        ScanBlock(block, txdb, addrpkdb,
            nTransactions, nInputs, nPubkeys, nDuplicates);
    }
    
    if (fDebugSmsg)
        printf("Found %u transactions, %u inputs, %u new public keys, %u duplicates.\n", nTransactions, nInputs, nPubkeys, nDuplicates);
    return true;
};

bool ScanChainForPublicKeys(CBlockIndex* pindexStart)
{
    printf("Scanning block chain for public keys.\n");
    int64_t nStart = GetTimeMillis();
    
    if (fDebugSmsg)
        printf("From height %u.\n", pindexStart->nHeight);
    
    // public keys are in txin.scriptSig
    // matching addresses are in scriptPubKey of txin's referenced output
    
    uint32_t nBlocks = 0;
    uint32_t nTransactions = 0;
    uint32_t nInputs = 0;
    uint32_t nPubkeys = 0;
    uint32_t nDuplicates = 0;
    
    {
        LOCK(cs_smsg);
    
        CSmesgPubKeyDB addrpkdb("cw");
        CTxDB txdb("r");
        
        CBlockIndex* pindex = pindexStart;
        while (pindex)
        {
            nBlocks++;
            CBlock block;
            block.ReadFromDisk(pindex, true);
            
            ScanBlock(block, txdb, addrpkdb,
                nTransactions, nInputs, nPubkeys, nDuplicates);
            
            pindex = pindex->pnext;
        };
    };
    //addrpkdb.Close(); // necessary?
    
    printf("Scanned %u blocks, %u transactions, %u inputs\n", nBlocks, nTransactions, nInputs);
    printf("Found %u public keys, %u duplicates.\n", nPubkeys, nDuplicates);
    printf("Took %lld ms\n", GetTimeMillis() - nStart);
    
    return true;
};

bool SecureMsgScanBlockChain()
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain)
    {
        
        CBlockIndex *pindexScan = pindexGenesisBlock;
        if (pindexScan == NULL)
        {
            printf("Error: pindexGenesisBlock not set.\n");
            return false;
        };
        
        // Put in try to catch errors opening db, 
        try
        {
            if (!ScanChainForPublicKeys(pindexScan))
                return false;
        } catch (std::exception& e)
        {
            printf("ScanChainForPublicKeys() threw: %s.\n", e.what());
            return false;
        };
    } else
    {
        printf("ScanChainForPublicKeys() Could not lock main.\n");
        return false;
    };
    
    return true;
};

int SecureMsgScanMessage(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload)
{
    /* 
    Check if message belongs to this node
    returns
        0 success,
        1 error
        2 no match
        
    */
    
    if (fDebugSmsg)
        printf("SecureMsgScanMessage()\n");
    
    std::string addressTo;
    MessageData msg; // placeholder
    bool fOwnMessage = false;
    
    // TODO: whitelist of addresses to receive on
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& entry, pwalletMain->mapAddressBook)
    {
        if (!IsMine(*pwalletMain, entry.first))
            continue;
        
        //printf("entry.first %s.\n", entry.first.ToString.c_str());
        CBitcoinAddress coinAddress(entry.first);
        addressTo = coinAddress.ToString();
        //printf("coinAddress: %s.\n", coinAddress.ToString().c_str());
        //printf("addressTo: %s.\n", addressTo.c_str());
        
        if (SecureMsgDecrypt(true, addressTo, pHeader, pPayload, nPayload, msg) == 0)
        {
            if (fDebugSmsg)
                printf("Decrypted message with %s.\n", addressTo.c_str());
            fOwnMessage = true;
            break;
        };
    };
    
    if (fOwnMessage)
    { // save to inbox
        {
            LOCK(cs_smsgInbox);
            
            CSmesgInboxDB dbInbox("cw");
            
            std::vector<unsigned char> vchKey;
            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], pHeader + 5, 8); // timestamp
            memcpy(&vchKey[8], pPayload, 8);    // sample
            
            SecInboxMsg smsgInbox;
            smsgInbox.timeReceived  = GetTime();
            smsgInbox.sAddrTo       = addressTo;
            //smsgInbox.vchMessage    = vchData;
            //smsgInbox.vchMessage    = std::vector<unsigned char>(vchData.begin() + n, vchData.begin() + n + SMSG_HDR_LEN + psmsg->nPayload);
            // -- data may not be contiguous
            smsgInbox.vchMessage.resize(SMSG_HDR_LEN + nPayload);
            memcpy(&smsgInbox.vchMessage[0], pHeader, SMSG_HDR_LEN);
            memcpy(&smsgInbox.vchMessage[SMSG_HDR_LEN], pPayload, nPayload);
            
            
            dbInbox.WriteSmesg(vchKey, smsgInbox);
            
            // -- must be a better way...
            std::vector<unsigned char> vchUnread;
            dbInbox.ReadUnread(vchUnread);
            
            vchUnread.insert(vchUnread.end(), vchKey.begin(), vchKey.end()); // append
            
            dbInbox.WriteUnread(vchUnread);
            
            NotifySecMsgInboxChanged(smsgInbox);
        }
    };
    
    return 0;
};

int SecureMsgGetLocalKey(CKeyID& ckid, CPubKey& cpkOut)
{
    CKey key;
    if (!pwalletMain->GetKey(ckid, key))
        return 4;
    
    key.SetCompressedPubKey(); // make sure key is compressed
    
    cpkOut = key.GetPubKey();
    if (!cpkOut.IsValid()
        || !cpkOut.IsCompressed())
    {
        printf("Public key is invalid %s.\n", ValueString(cpkOut.Raw()).c_str());
        return 1;
    };
    return 0;
};

int SecureMsgGetLocalPublicKey(std::string& strAddress, std::string& strPublicKey)
{
    /* returns
        0 success,
        1 error
        2 invalid address
        3 address does not refer to a key
        4 address not in wallet
    */
    
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        return 2; // Invalid CinniCoin address
    
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        return 3;
    
    int rv;
    CPubKey pubKey;
    if ((rv = SecureMsgGetLocalKey(keyID, pubKey)) != 0)
        return rv;
    
    //printf("public key %s.\n", ValueString(pubKey.Raw()).c_str());
    strPublicKey = EncodeBase58(pubKey.Raw());
    
    //std::string keyb58 = EncodeBase58(pubKey.Raw());
    //printf("keyb58 %s.\n", keyb58.c_str());
    return 0;
};

int SecureMsgGetStoredKey(CKeyID& ckid, CPubKey& cpkOut)
{
    /* returns
        0 success,
        1 error
        2 public key not in database
    */
    if (fDebugSmsg)
        printf("SecureMsgGetStoredKey().\n");
    
    CSmesgPubKeyDB addrpkdb("r");
    
    if (!addrpkdb.ReadPK(ckid, cpkOut))
    {
        //printf("addrpkdb.Read failed: %s.\n", coinAddress.ToString().c_str());
        return 2;
    };
    //printf("cpkOut: %s.\n", ValueString(cpkOut.Raw()).c_str());
    
    addrpkdb.Close(); // necessary?
    
    return 0;
};

int SecureMsgAddAddress(std::string& address, std::string& publicKey)
{
    /*
        Add address and matching public key to the database
        address and publicKey are in base58
        
        returns
            0 success
            1 address is invalid
            2 publicKey is invalid
            3 publicKey != address
            4 address is already in db
            5 error
    */
    
    CBitcoinAddress coinAddress(address);
    //printf("coinAddress: %s.\n", coinAddress.ToString().c_str());
    if (!coinAddress.IsValid())
    {
        printf("address is not valid: %s.\n", address.c_str());
        return 1;
    };
    
    CKeyID hashKey;
    
    if (!coinAddress.GetKeyID(hashKey))
    {
        printf("coinAddress.GetKeyID failed: %s.\n", coinAddress.ToString().c_str());
        return 1;
    };
    
    std::vector<unsigned char> vchTest;
    DecodeBase58(publicKey, vchTest);
    CPubKey pubKey(vchTest);
    
    // -- check that public key matches address hash
    CKey keyT;
    if (!keyT.SetPubKey(pubKey))
    {
        printf("SetPubKey failed.\n");
        return 2;
    };
    
    keyT.SetCompressedPubKey();
    CPubKey pubKeyT = keyT.GetPubKey();
    
    //CKeyID ckidT = pubKeyT.GetID();
    CBitcoinAddress addressT(address);
    //printf("addressT %s.\n", addressT.ToString().c_str());
    
    if (addressT.ToString().compare(address) != 0)
    {
        printf("Public key does not hash to address, addressT %s.\n", addressT.ToString().c_str());
        return 3;
    };
    
    return SecureMsgInsertAddress(hashKey, pubKey);
};

int SecureMsgRetrieve(SecMsgToken &token, std::vector<unsigned char>& vchData)
{
    if (fDebugSmsg)
        printf("SecureMsgRetrieve() %ld.\n", token.timestamp);
    
    // -- has cs_smsg lock from SecureMsgReceiveData
    
   // std::vector<unsigned char> vchData;
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    
    int64_t bucket = token.timestamp - (token.timestamp % SMSG_BUCKET_LEN);
    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    
    fs::path fullpath = pathSmsgDir / fileName;
    
    //printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    FILE *fp;
    if (!(fp = fopen(fullpath.string().c_str(), "r")))
    {
        printf("Error opening file: %s\n", strerror(errno));
        return 1;
    };
    
    //printf("token.offset: %ld\n", token.offset);
    
    if (fseek(fp, token.offset, SEEK_SET) != 0)
    {
        printf("fseek, strerror: %s.\n", strerror(errno));
        fclose(fp);
        return 1;
    };
    
    SecureMessage smsg;
    if (fread(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
    {
        printf("fread header failed: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    };
    
    vchData.resize(SMSG_HDR_LEN + smsg.nPayload);
    
    memcpy(&vchData[0], &smsg.hash[0], SMSG_HDR_LEN);
    
    if (fread(&vchData[SMSG_HDR_LEN], sizeof(unsigned char), smsg.nPayload, fp) != smsg.nPayload)
    {
        printf("fread data failed: %s\n", strerror(errno));
        fclose(fp);
        return 1;
    };
    
    
    fclose(fp);
    
    return 0;
};

int SecureMsgReceive(std::vector<unsigned char>& vchData)
{
    if (fDebugSmsg)
        printf("SecureMsgReceive().\n");
    
    if (vchData.size() < 12) // nBunch4 + timestamp8
    {
        printf("Error: not enough data.\n");
        return 1;
    };
    
    uint32_t nBunch;
    int64_t bktTime;
    
    memcpy(&nBunch, &vchData[0], 4);
    memcpy(&bktTime, &vchData[4], 8);
    
    if (nBunch == 0 || nBunch > 500)
    {
        printf("Error: Invalid no. messages in bunch %u.\n", nBunch);
        return 1;
    };
    
    printf("nBunch %u.\n", nBunch);
    
    
    // TODO: check bktTime (bucket may not exist - will be created here)
    
    uint32_t n = 12;
    
    for (uint32_t i = 0; i < nBunch; ++i)
    {
        if (vchData.size() - n < SMSG_HDR_LEN)
        {
            printf("Error: not enough data, n = %u.\n", n);
            break;
        };
        
        SecureMessage* psmsg;
        psmsg = (SecureMessage*) &vchData[n];
        
        //printf("psmsg->nPayload %u.\n", psmsg->nPayload);
        
        // false == don't hash bucket
        if (SecureMsgStore(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload, false) != 0)
        {
            // message dropped
            break; // continue?
        };
        
        
        if (SecureMsgScanMessage(&vchData[n], &vchData[n + SMSG_HDR_LEN], psmsg->nPayload) != 0)
        {
            // message recipient is not this node (or failed)
        };
        
        n += SMSG_HDR_LEN + psmsg->nPayload;
    };
    
    // if messages have been added, bucket must exist now
    std::map<int64_t, SecMsgBucket>::iterator itb;
    itb = smsgSets.find(bktTime);
    if (itb == smsgSets.end())
    {
        if (fDebugSmsg)
            printf("Don't have bucket %ld.\n", bktTime);
        return 1;
    };
    
    itb->second.hashBucket();
    
    return 0;
};

int SecureMsgStore(unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, bool fUpdateBucket)
{
    if (fDebugSmsg)
        printf("SecureMsgStore()\n");
    
    if (!pHeader
        || !pPayload)
    {
        printf("Error: null pointer to header or payload.\n");
        return 1;
    };
    
    SecureMessage* psmsg;
    psmsg = (SecureMessage*) pHeader;
    
    
    long int ofs;
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    fs::create_directory(pathSmsgDir);
    
    int64_t now = GetTime();
    if (psmsg->timestamp > now)
    {
        printf("Message > now.\n");
        return 1;
    } else
    if (psmsg->timestamp < now - SMSG_RETENTION)
    {
        printf("Message < SMSG_RETENTION.\n");
        return 1;
    };
    
    int64_t bucket = psmsg->timestamp - (psmsg->timestamp % SMSG_BUCKET_LEN);
    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    
    fs::path fullpath = pathSmsgDir / fileName;
    
    if (fDebugSmsg)
        printf("storing msg in %s.\n", fullpath.string().c_str());
    
    {
        // -- must lock cs_smsg before calling
        //LOCK(cs_smsg);
        
        SecMsgToken token(psmsg->timestamp, pPayload, nPayload, 0);
        
        std::set<SecMsgToken>::iterator it;
        it = smsgSets[bucket].setTokens.find(token);
        if (it != smsgSets[bucket].setTokens.end())
        {
            printf("Already have message.\n");
            return 1;
        };
        
        FILE *fp;
        
        if (!(fp = fopen(fullpath.string().c_str(), "a")))
        {
            printf("Error opening file: %s\n", strerror(errno));
            return 1;
        };
        
        
        ofs = ftell(fp);
        
        if (fwrite(pHeader, sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
            || fwrite(pPayload, sizeof(unsigned char), nPayload, fp) != nPayload)
        {
            printf("fwrite failed: %s\n", strerror(errno));
            fclose(fp);
            return 1;
        };
        
        token.offset = ofs;
        //unsigned char hash[4];
        
        fclose(fp);
        
        smsgSets[bucket].setTokens.insert(token);
        
        if (fUpdateBucket)
            smsgSets[bucket].hashBucket();
    };
    
    return 0;
};

int SecureMsgStore(SecureMessage& smsg, bool fUpdateBucket)
{
    return SecureMsgStore(&smsg.hash[0], smsg.pPayload, smsg.nPayload, fUpdateBucket);
};

int SecureMsgEncrypt(SecureMessage& smsg, std::string& addressFrom, std::string& addressTo, std::string& message)
{
    /* Create a secure message
    
        returns
            2       message is too long.
            3       addressFrom is invalid.
            4       addressTo is invalid.
            5       Could not get public key for addressTo.
            6       ECDH_compute_key failed
            7       Could not get private key for addressFrom.
            8       Could not allocate memory.
            9       Could not compress message data.
            10      Could not generate MAC.
            11      Encrypt failed.
    */
    
    if (fDebugSmsg)
        printf("SecureMsgEncrypt(%s, %s, ...)\n", addressFrom.c_str(), addressTo.c_str());
    
    if (message.size() > SMSG_MAX_MSG_BYTES)
    {
        printf("Message is too long, %lu.\n", message.size());
        return 2;
    };
    
    smsg.version = 1;
    smsg.timestamp = time(NULL);
    
    memset(smsg.destHash, 0, 20); // Not used yet
    memset(smsg.hash, 0, 4); // Not used yet (checksum)
    
    bool fSendAnonymous;
    CBitcoinAddress coinAddrFrom;
    CKeyID ckidFrom;
    CKey keyFrom;
    
    if (addressFrom.compare("anon") == 0)
    {
        fSendAnonymous = true;
        
    } else
    {
        fSendAnonymous = false;
        
        if (!coinAddrFrom.SetString(addressFrom))
        {
            printf("addressFrom is not valid.\n");
            return 3;
        };
        
        if (!coinAddrFrom.GetKeyID(ckidFrom))
        {
            printf("coinAddrFrom.GetKeyID failed: %s.\n", coinAddrFrom.ToString().c_str());
            return 3;
        };
    };
    
    
    CBitcoinAddress coinAddrDest;
    CKeyID ckidDest;
    
    if (!coinAddrDest.SetString(addressTo))
    {
        printf("addressTo is not valid.\n");
        return 4;
    };
    
    //printf("coinAddrDest: %s.\n", coinAddrDest.ToString().c_str());
    if (!coinAddrDest.GetKeyID(ckidDest))
    {
        printf("coinAddrDest.GetKeyID failed: %s.\n", coinAddrDest.ToString().c_str());
        return 4;
    };
    
    // -- public key K is the destination address
    CPubKey cpkDestK;
    if (SecureMsgGetStoredKey(ckidDest, cpkDestK) != 0)
    {
        // -- maybe it's a local key (outbox?)
        if (SecureMsgGetLocalKey(ckidDest, cpkDestK) != 0)
        {
            printf("Could not get public key for destination address.\n");
            return 5;
        };
    };
    
    
    // -- Generate 16 random bytes using a secure random number generator. Call them IV.
    
    RandAddSeedPerfmon();
    
    RAND_bytes(&smsg.iv[0], 16);
    
    
    // -- Generate a new random EC key pair with private key called r and public key called R.
    
    CKey keyR;
    keyR.MakeNewKey(true); // make compressed key
    
    // -- Do an EC point multiply with public key K and private key r. This gives you public key P. 
    
    //printf("cpkDestK: %s.\n", ValueString(cpkDestK.Raw()).c_str());
    CKey keyK;
    if (!keyK.SetPubKey(cpkDestK))
    {
        printf("Could not set pubkey for K: %s.\n", ValueString(cpkDestK.Raw()).c_str());
        return 4; // address to is invalid
    };
    
    std::vector<unsigned char> vchP;
    vchP.resize(32);
    EC_KEY* pkeyr = keyR.GetECKey();
    EC_KEY* pkeyK = keyK.GetECKey();
    
    // always seems to be 32, worth checking?
    //int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pkeyr));
    //int secret_len = (field_size+7)/8;
    //printf("secret_len %d.\n", secret_len);
    
    // ECDH_compute_key returns the same P if fed compressed or uncompressed public keys
    ECDH_set_method(pkeyr, ECDH_OpenSSL());
    int lenP = ECDH_compute_key(&vchP[0], 32, EC_KEY_get0_public_key(pkeyK), pkeyr, NULL);
    
    if (lenP != 32)
    {
        printf("ECDH_compute_key failed, lenP: %d.\n", lenP);
        return 6;
    };
    
    //printf("lenP: %d.\n", lenP);
    //printf("P: %s.\n", ValueString(vchP).c_str());
    
    CPubKey cpkR = keyR.GetPubKey();
    //printf("cpkR: %s.\n", ValueString(cpkR.Raw()).c_str());
    if (!cpkR.IsValid()
        || !cpkR.IsCompressed())
    {
        printf("Could not get public key for key R.\n");
        return 1;
    };
    //printf("cpkR.Raw().size() %d.\n", cpkR.Raw().size());
    //printf("compressed cpkR %s.\n", ValueString(cpkR.Raw()).c_str());
    memcpy(smsg.cpkR, &cpkR.Raw()[0], 33);
    
    
    // -- Use public key P and calculate the SHA512 hash H. 
    
    std::vector<unsigned char> vchHashed;
    vchHashed.resize(64); // 512
    
    // X component where?, is ECDH_compute_key returning a compressed key? could be as it's only 32 bytes
    SHA512(&vchP[0], vchP.size(), (unsigned char*)&vchHashed[0]);
    //printf("SHA512(P): %s.\n", ValueString(vchHashed).c_str());
    
    // -- The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
    std::vector<unsigned char> key_e(&vchHashed[0], &vchHashed[0]+32);
    std::vector<unsigned char> key_m(&vchHashed[32], &vchHashed[32]+32);
    
    //printf("key_e: %s.\n", ValueString(key_e).c_str());
    //printf("key_m: %s.\n", ValueString(key_m).c_str());
    
    
    std::vector<unsigned char> vchPayload;
    std::vector<unsigned char> vchCompressed;
    unsigned char* pMsgData;
    uint32_t lenMsgData;
    
    uint32_t lenMsg = message.size();
    //printf("lenMsg: %d.\n", lenMsg);
    if (lenMsg > 128)
    {
        // -- only compress if over 128 bytes
        int worstCase = LZ4_compressBound(message.size());
        vchCompressed.resize(worstCase);
        int lenComp = LZ4_compress((char*)message.c_str(), (char*)&vchCompressed[0], lenMsg);
        if (lenComp < 1)
        {
            printf("Could not compress message data.\n");
            return 9;
        };
        
        pMsgData = &vchCompressed[0];
        lenMsgData = lenComp;
        
    } else
    {
        pMsgData = (unsigned char*)message.c_str();
        lenMsgData = lenMsg;
    };
    
    if (fSendAnonymous)
    {
        vchPayload.resize(9 + lenMsgData);
        memcpy(&vchPayload[9], pMsgData, lenMsgData);
        
        vchPayload[0] = 250; // id as anonymous message
        // next 4 bytes are unused - there to ensure encrypted payload always > 8 bytes
        memcpy(&vchPayload[5], &lenMsg, 4); // length of uncompressed plain text
    } else
    {
        vchPayload.resize(SMSG_PL_HDR_LEN + lenMsgData);
        memcpy(&vchPayload[SMSG_PL_HDR_LEN], pMsgData, lenMsgData);
        // -- compact signature proves ownership of from address and allows the public key to be recovered, recipient can always reply.
        if (!pwalletMain->GetKey(ckidFrom, keyFrom))
        {
            printf("Could not get private key for addressFrom.\n");
            return 7;
        };
        
        // -- sign the plaintext
        std::vector<unsigned char> vchSignature;
        vchSignature.resize(65);
        keyFrom.SignCompact(Hash(message.begin(), message.end()), vchSignature);
        
        
        // Save some bytes by sending address raw
        vchPayload[0] = (static_cast<CBitcoinAddress_B*>(&coinAddrFrom))->getVersion(); // vchPayload[0] = coinAddrDest.nVersion;
        memcpy(&vchPayload[1], (static_cast<CKeyID_B*>(&ckidFrom))->GetPPN(), 20); // memcpy(&vchPayload[1], ckidDest.pn, 20);
        
        memcpy(&vchPayload[1+20], &vchSignature[0], vchSignature.size());
        memcpy(&vchPayload[1+20+65], &lenMsg, 4); // length of uncompressed plain text
        //printf("message: %s.\n", message.c_str());
    };
    
    
    SMsgCrypter crypter;
    crypter.SetKey(key_e, smsg.iv);
    std::vector<unsigned char> vchCiphertext;
    
    if (!crypter.Encrypt(&vchPayload[0], vchPayload.size(), vchCiphertext))
    {
        printf("crypter.Encrypt failed.\n");
        return 11;
    };
    
    try {
        smsg.pPayload = new unsigned char[vchCiphertext.size()];
    } catch (std::exception& e)
    {
        printf("Could not allocate pPayload, exception: %s.\n", e.what());
        return 8;
    };
    
    memcpy(smsg.pPayload, &vchCiphertext[0], vchCiphertext.size());
    
    smsg.nPayload = vchCiphertext.size();
    
    
    // Calculate a 32 byte MAC with HMACSHA256, using key_m as salt
    // Message authentication code, (hash of timestamp + destination + payload)
    
    bool fHmacOk = true;
    unsigned int nBytes = 32;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    
    if (!HMAC_Init_ex(&ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(&ctx, (unsigned char*) &smsg.timestamp, sizeof(smsg.timestamp))
        || !HMAC_Update(&ctx, (unsigned char*) &smsg.destHash[0], sizeof(smsg.destHash))
        || !HMAC_Update(&ctx, &vchCiphertext[0], vchCiphertext.size())
        || !HMAC_Final(&ctx, smsg.mac, &nBytes)
        || nBytes != 32)
        fHmacOk = false;
    
    HMAC_CTX_cleanup(&ctx);
    
    if (!fHmacOk)
    {
        printf("Could not generate MAC.\n");
        return 10;
    };
    
    // todo hash checksum
    
    return 0;
}

int SecureMsgSend(std::string& addressFrom, std::string& addressTo, std::string& message, std::string& sError)
{
    /* Encrypt secure message, and place it on the network
        Make a copy of the message to sender's first address and place in outbox
    
        Using the same method as bitmessage.
        If bitmessage is secure this should be too.
        https://bitmessage.org/wiki/Encryption
        
        Some differences:
        bitmessage seems to use curve sect283r1
        Cinnicoin addresses use secp256k1
        
    */
    
    if (fDebugSmsg)
        printf("SecureMsgSend(%s, %s, ...)\n", addressFrom.c_str(), addressTo.c_str());
    
    if (message.size() > SMSG_MAX_MSG_BYTES)
    {
        std::ostringstream oss;
        oss << message.size() << " > " << SMSG_MAX_MSG_BYTES;
        sError = "Message is too long, " + oss.str();
        printf("Message is too long, %lu.\n", message.size());
        return 1;
    };
    
    
    int rv;
    SecureMessage smsg;
    
    if ((rv = SecureMsgEncrypt(smsg, addressFrom, addressTo, message)) != 0)
    {
        printf("SecureMsgSend(), encrypt for recipient failed.\n");
        
        switch(rv)
        {
            case 2:  sError = "Message is too long.";                       break;
            case 3:  sError = "Invalid addressFrom.";                       break;
            case 4:  sError = "Invalid addressTo.";                         break;
            case 5:  sError = "Could not get public key for addressTo.";    break;
            case 6:  sError = "ECDH_compute_key failed.";                   break;
            case 7:  sError = "Could not get private key for addressFrom."; break;
            case 8:  sError = "Could not allocate memory.";                 break;
            case 9:  sError = "Could not compress message data.";           break;
            case 10: sError = "Could not generate MAC.";                    break;
            case 11: sError = "Encrypt failed.";                            break;
            default: sError = "Unspecified Error.";                         break;
        };
        
        return rv;
    };
    
    // -- add to message store
    {
        LOCK(cs_smsg);
        if (SecureMsgStore(smsg, true) != 0)
        {
            sError = "Could not store message.";
            return 1;
        };
    }
    
    // -- test if message was sent to self
    if (SecureMsgScanMessage(&smsg.hash[0], smsg.pPayload, smsg.nPayload) != 0)
    {
        // message recipient is not this node (or failed)
    };
    
    
    
    if (fDebugSmsg)
        printf("Encrypting message for outbox.\n");
    //  -- for outbox create a copy encrypted for owned address
    //     if the wallet is encrypted private key needed to decrypt will be unavailable
    
    
    std::string addressOutbox;
    CBitcoinAddress coinAddrOutbox;
    
    BOOST_FOREACH(const PAIRTYPE(CBitcoinAddress, std::string)& item, pwalletMain->mapAddressBook)
    {
        const CBitcoinAddress& address = item.first;
        //const std::string& strName = item.second;
        
        addressOutbox = address.ToString();
        if (!coinAddrOutbox.SetString(addressOutbox)) // test valid
        {
            continue;
        };
        //if (strName == "" || strName == "0") // just get first valid address (what happens if user renames account)
        break;
    };
    
    if (fDebugSmsg)
        printf("Encrypting a copy for outbox, using address %s\n", addressOutbox.c_str());
    
    SecureMessage smsgForOutbox;
    if ((rv = SecureMsgEncrypt(smsgForOutbox, addressFrom, addressOutbox, message)) != 0)
    {
        printf("SecureMsgSend(), encrypt for outbox failed, %d.\n", rv);
    } else
    { // save to outbox db
        {
            LOCK(cs_smsgOutbox);
            
            CSmesgOutboxDB dbOutbox("cw");
            
            std::vector<unsigned char> vchKey;
            vchKey.resize(16); // timestamp8 + sample8
            memcpy(&vchKey[0], &smsgForOutbox.hash[0] + 5, 8);   // timestamp
            memcpy(&vchKey[8], &smsgForOutbox.pPayload, 8);  // sample
            
            SecOutboxMsg smsgOutbox;
            
            smsgOutbox.timeReceived  = GetTime();
            smsgOutbox.sAddrTo       = addressTo;
            smsgOutbox.sAddrOutbox   = addressOutbox;
            
            smsgOutbox.vchMessage.resize(SMSG_HDR_LEN + smsgForOutbox.nPayload);
            memcpy(&smsgOutbox.vchMessage[0], &smsgForOutbox.hash[0], SMSG_HDR_LEN);
            memcpy(&smsgOutbox.vchMessage[SMSG_HDR_LEN], smsgForOutbox.pPayload, smsgForOutbox.nPayload);
            
            
            dbOutbox.WriteSmesg(vchKey, smsgOutbox);
            
            NotifySecMsgOutboxChanged(smsgOutbox);
        }
    }
    
    //addressTo
    
    
    if (fDebugSmsg)
        printf("Secure message sent to %s.\n", addressTo.c_str());
    
    return 0;
};


int SecureMsgDecrypt(bool fTestOnly, std::string& address, unsigned char *pHeader, unsigned char *pPayload, uint32_t nPayload, MessageData& msg)
{
    // TODO validate SecureMessage, check hash, nPayload, etc
    
    if (fDebugSmsg)
        printf("SecureMsgDecrypt(), using %s, testonly %d.\n", address.c_str(), fTestOnly);
    
    if (!pHeader
        || !pPayload)
    {
        printf("Error: null pointer to header or payload.\n");
        return 1;
    };
    
    SecureMessage* psmsg;
    psmsg = (SecureMessage*) pHeader;
    
    // -- Fetch private key k, used to decrypt
    CBitcoinAddress coinAddrDest;
    if (!coinAddrDest.SetString(address))
    {
        printf("address is not valid.\n");
        return 1;
    };
    
    //printf("coinAddrDest: %s.\n", coinAddrDest.ToString().c_str());
    CKeyID ckidDest;
    if (!coinAddrDest.GetKeyID(ckidDest))
    {
        printf("coinAddrDest.GetKeyID failed: %s.\n", coinAddrDest.ToString().c_str());
        return 1;
    };
    
    CKey keyDest;
    if (!pwalletMain->GetKey(ckidDest, keyDest))
    {
        printf("Could not get private key for addressDest.\n");
        return 1;
    };
    
    
    CKey keyR;
    std::vector<unsigned char> vchR(psmsg->cpkR, psmsg->cpkR+33); // would be neater to override CPubKey() instead
    CPubKey cpkR(vchR);
    if (!cpkR.IsValid())
    {
        printf("Could not get public key for key R.\n");
        return 1;
    };
    
    if (!keyR.SetPubKey(cpkR))
    {
        printf("Could not set pubkey for R: %s.\n", ValueString(cpkR.Raw()).c_str());
        return 1;
    };
    
    //printf("compressed cpkR %s.\n", ValueString(cpkR.Raw()).c_str());
    
    cpkR = keyR.GetPubKey();
    if (!cpkR.IsValid()
        || !cpkR.IsCompressed())
    {
        printf("Could not get compressed public key for key R.\n");
        return 1;
    };
    
    // -- Do an EC point multiply with private key k and public key R. This gives you public key P. 
    
    std::vector<unsigned char> vchP;
    vchP.resize(32);
    EC_KEY* pkeyk = keyDest.GetECKey();
    EC_KEY* pkeyR = keyR.GetECKey();
    
    ECDH_set_method(pkeyk, ECDH_OpenSSL());
    int lenPdec = ECDH_compute_key(&vchP[0], 32, EC_KEY_get0_public_key(pkeyR), pkeyk, NULL);
    
    if (lenPdec != 32)
    {
        printf("ECDH_compute_key failed, lenPdec: %d.\n", lenPdec);
        return 1;
    };
    
    //printf("lenPdec: %d.\n", lenPdec);
    //printf("P dec: %s.\n", ValueString(vchP).c_str());
    
    // -- Use public key P to calculate the SHA512 hash H. 
    
    std::vector<unsigned char> vchHashedDec;
    vchHashedDec.resize(64); // 512
    
    
    SHA512(&vchP[0], vchP.size(), (unsigned char*)&vchHashedDec[0]);
    //printf("SHA512(P) dec: %s.\n", ValueString(vchHashedDec).c_str());
    
    // The first 32 bytes of H are called key_e and the last 32 bytes are called key_m. 
    std::vector<unsigned char> key_e(&vchHashedDec[0], &vchHashedDec[0]+32);
    std::vector<unsigned char> key_m(&vchHashedDec[32], &vchHashedDec[32]+32);
    
    //printf("key_e: %s.\n", ValueString(key_e).c_str());
    //printf("key_m: %s.\n", ValueString(key_m).c_str());
    
    // -- Message authentication code, (hash of timestamp + destination + payload)
    
    unsigned char MAC[32];
    bool fHmacOk = true;
    unsigned int nBytes = 32;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    
    if (!HMAC_Init_ex(&ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(&ctx, (unsigned char*) &psmsg->timestamp, sizeof(psmsg->timestamp))
        || !HMAC_Update(&ctx, (unsigned char*) &psmsg->destHash[0], sizeof(psmsg->destHash))
        || !HMAC_Update(&ctx, pPayload, nPayload)
        || !HMAC_Final(&ctx, MAC, &nBytes)
        || nBytes != 32)
        fHmacOk = false;
    
    HMAC_CTX_cleanup(&ctx);
    
    if (!fHmacOk)
    {
        printf("Could not generate MAC.\n");
        return 1;
    };
    
    /*
    printf("MAC: ");
    for (int i = 0; i < 32; ++i)
      printf("%x", MAC[i]);
    printf("\n");
    */
    if (memcmp(MAC, psmsg->mac, 32) != 0)
    {
        printf("MAC does not match.\n");
        return 1;
    };
    
    if (fTestOnly)
        return 0;
    
    
    SMsgCrypter crypter;
    crypter.SetKey(key_e, psmsg->iv);
    std::vector<unsigned char> vchPayload;
    if (!crypter.Decrypt(pPayload, nPayload, vchPayload))
    {
        printf("Decrypt failed.\n");
        return 1;
    };
    
    msg.timestamp = psmsg->timestamp;
    uint32_t lenData;
    uint32_t lenPlain;
    
    unsigned char* pMsgData;
    bool fFromAnonymous;
    if ((uint32_t)vchPayload[0] == 250)
    {
        fFromAnonymous = true;
        lenData = vchPayload.size() - (9);
        memcpy(&lenPlain, &vchPayload[5], 4);
        pMsgData = &vchPayload[9];
    } else
    {
        fFromAnonymous = false;
        lenData = vchPayload.size() - (SMSG_PL_HDR_LEN);
        memcpy(&lenPlain, &vchPayload[1+20+65], 4);
        pMsgData = &vchPayload[SMSG_PL_HDR_LEN];
    };
    
    msg.vchMessage.resize(lenPlain + 1);
    
    if (lenPlain > 128)
    { // decompress
        if (LZ4_decompress_safe((char*) pMsgData, (char*) &msg.vchMessage[0], lenData, lenPlain) != (int) lenPlain)
        {
            printf("Could not decompress message data.\n");
            return 1;
        };
    } else
    { // plaintext
        memcpy(&msg.vchMessage[0], pMsgData, lenPlain);
    };
    
    msg.vchMessage[lenPlain] = '\0';
    //printf("msg.vchMessage %s.\n", &msg.vchMessage[0]);
    
    if (fFromAnonymous)
    {
        printf("Anonymous sender.\n");
        
        msg.sFromAddress = "anon";
    } else
    {
        std::vector<unsigned char> vchUint160;
        vchUint160.resize(20);
        
        memcpy(&vchUint160[0], &vchPayload[1], 20);
        
        uint160 ui160(vchUint160);
        CKeyID ckidFrom(ui160);
        
        CBitcoinAddress coinAddrFrom;
        coinAddrFrom.Set(ckidFrom);
        if (!coinAddrFrom.IsValid())
        {
            printf("From Addess is invalid.\n");
            return 1;
        };
        //printf("coinAddrFrom %s.\n", coinAddrFrom.ToString().c_str());
        
        std::vector<unsigned char> vchSig;
        vchSig.resize(65);
        
        memcpy(&vchSig[0], &vchPayload[1+20], 65);
        
        
        CKey keyFrom;
        keyFrom.SetCompactSignature(Hash(msg.vchMessage.begin(), msg.vchMessage.end()-1), vchSig);
        CPubKey cpkFromSig = keyFrom.GetPubKey();
        if (!cpkFromSig.IsValid())
        {
            printf("Signature validation failed.\n");
            return 1;
        };
        
        // Need the address for the compressed public key here
        CBitcoinAddress coinAddrFromSig;
        coinAddrFromSig.Set(cpkFromSig.GetID());
        
        if (!(coinAddrFrom == coinAddrFromSig))
        {
            printf("Signature validation failed.\n");
            return 1;
        };
        
        cpkFromSig = keyFrom.GetPubKey();
        
        int rv = 5;
        try {
            rv = SecureMsgInsertAddress(ckidFrom, cpkFromSig);
        } catch (std::exception& e) {
            printf("SecureMsgInsertAddress(), exception: %s.\n", e.what());
            //return 1;
        };
        
        switch(rv)
        {
            case 0:
                printf("Sender public key added to db.\n");
                break;
            case 4:
                printf("Sender public key already in db.\n");
                break;
            default:
                printf("Error adding sender public key to db.\n");
                break;
        };
        
        //printf("coinAddrFrom %s.\n", coinAddrFrom.ToString().c_str());
        
        msg.sFromAddress = coinAddrFrom.ToString();
    };
    
    if (fDebugSmsg)
        printf("Decrypted message for %s.\n", address.c_str());
    
    return 0;
};

int SecureMsgDecrypt(bool fTestOnly, std::string& address, SecureMessage& smsg, MessageData& msg)
{
    // -- address is the owned address to decrypt with.
    //    if fTestOnly return after checking MAC
    
    return SecureMsgDecrypt(fTestOnly, address, &smsg.hash[0], smsg.pPayload, smsg.nPayload, msg);
};
