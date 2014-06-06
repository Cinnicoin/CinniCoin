// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
Notes:
    Running with -debug could leave to and from address hashes and public keys in the log.
    
*/

#include "emessage.h"

#include <stdint.h>
#include <time.h>
#include <map>
#include <stdexcept>
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

//std::vector<SecureMessage> smsgStore; // temporary

//std::vector<SecureMessage*> smsgUnsent;



//std::vector<SecMsgLocation> smsgSend; // temporary

//std::vector<SecMsgLocation> smsgStored; // move to db?

// TODO: For buckets older than current, only need to store length and hash in memory
// TODO: move set into a class then can add timeChanged, hash etc.
std::map<int64_t, std::set<SecMsgToken> > smsgSets;



CCriticalSection cs_smsg;

namespace fs = boost::filesystem;

bool SMsgCrypter::SetKey(const std::vector<unsigned char>& chNewKey, unsigned char* chNewIV)
{
    // -- for EVP_aes_256_cbc() key must be 256 bit, iv must be 128 bit.
    memcpy(&chKey[0], &chNewKey[0], sizeof(chKey));
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
        if (delay < 10) // check every 10 seconds
            continue;
        delay = 0;
        
        int64_t now = GetTime();
        printf("SecureMsgThread %ld \n", now);
        //printf("SecureMsgThread %ld \n", now - (now % 60));
        
        int64_t cutoffTime = now - SMSG_RETENTION;
        
        std::map<int64_t, std::set<SecMsgToken> >::iterator it;
        it = smsgSets.begin();
        
        while (it != smsgSets.end())
        {
            if (fDebug)
                printf("checking bucket %ld, size %d \n", it->first, it->second.size());
            if (it->first < cutoffTime)
            {
                printf("Removing bucket %ld \n", it->first);
                std::string fileName = boost::lexical_cast<std::string>(it->first) + "_01.dat";
                fs::path fullPath = GetDataDir() / "smsgStore" / fileName;
                if (fs::exists(fullPath))
                    fs::remove(fullPath);
                else
                    printf("Path %s does not exist \n", fullPath.string().c_str());
                
                
                smsgSets.erase(it++);
            } else
                ++it;
        };
    };
    
    printf("ThreadSecureMsg exited.\n");
};


/** called from AppInit2() in init.cpp */
bool SecureMsgStart()
{
    printf("Starting secure messaging.\n");
    
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
            
            if (fDebug)
                printf("Processing file: %s.\n", fileName.c_str());
            
            // TODO files could be split if > 2GB
            // time_no.dat
            size_t sep = fileName.find_last_of("_");
            if (sep == std::string::npos)
                continue;
            
            std::string stime = fileName.substr(0, sep);
            
            int64_t fileTime = boost::lexical_cast<int64_t>(stime);
            
            printf("fileTime %ld.\n", fileTime);
            
            if (fileTime < now - SMSG_RETENTION)
            {
                printf("Dropping message set %ld.\n", fileTime);
                fs::remove((*itd).path());
                continue;
            };
            
            //smsgSets.insert(std::map<int64_t, std::set<SecMsgToken> >::value_type(fileTime, std::set<SecMsgToken>));
            //smsgSets.insert(std::make_pair(fileTime, std::set<SecMsgToken> ));
            
            SecureMessage smsg;
            std::set<SecMsgToken>& tokenSet = smsgSets[fileTime];
            
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
                    
                    printf("smsg.nPayload %d\n", smsg.nPayload);
                    
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
                    }
                    
                    tokenSet.insert(token);
                };
                
                fclose(fp);
            };
            
            printf("e smsgSets[fileTime].size() %ld, %d\n", fileTime, smsgSets[fileTime].size());
            
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
    printf("Stopping secure messaging.\n");
    
    
    return true;
};


bool SecureMsgReceiveData(CNode* pfrom, std::string strCommand, CDataStream& vRecv)
{
    printf("SecureMsgReceiveData() %s %s.\n", pfrom->addrName.c_str(), strCommand.c_str());
    
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    {
        // break up?
        LOCK(cs_smsg);
    
    //vector<char> vHeaders;
    //pto->PushMessage("smsgQuery", "enabled");
    if (strCommand == "smsgPong")
    {
        pfrom->smsgData.enabled = true;
    }
    if (strCommand == "smsgPing")
    {
        //printf("got smsgPing.\n");
        pfrom->PushMessage("smsgPong");
    } else
    if (strCommand == "smsgMsg")
    {
        //printf("got smsgPing.\n");
        //pfrom->PushMessage("smsgPong");
        
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        printf("vchData.size() %d.\n", vchData.size());
        
        SecureMsgReceive(vchData);
        
        
    } else
    if (strCommand == "smsgInv")
    {
        printf("got smsgInv.\n");
        //pfrom->PushMessage("smsgPong");
        
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        printf("vchData.size() %d.\n", vchData.size());
        
        if (vchData.size() < 4)
            return false;
        
        uint32_t nbuckets = smsgSets.size(); // uint16?
        
        uint32_t nmessage;
        
        memcpy(&nmessage, &vchData[0], 4);
        printf("Remote node has %d buckets, this has %d.\n", nmessage, nbuckets);
        
        if (vchData.size() < 4 + nmessage*12)
            return false;
        
        std::vector<unsigned char> vchDataOut;
        vchDataOut.resize(8);
        
        unsigned char *p;
        p = &vchData[4];
        for (uint32_t i = 0; i < nmessage; ++i)
        {
            int64_t time;
            uint32_t ncontent;
            memcpy(&time, p, 8);
            memcpy(&ncontent, p+8, 4);
            //printf("Remote node has %d buckets, this has %d.\n", nmessage, nbuckets);
            printf("bucket %ld %d.\n", time, ncontent);
            p += 12;
            
            // TODO: check hash of all messages in bucket
            if (smsgSets[time].size() < ncontent)
            {
                memcpy(&vchDataOut[0], &time, 8);
                pfrom->PushMessage("smsgShow", vchDataOut);
            };
            
        };

        
        
        //SecureMsgReceive(vchData);
        
        
    } else
    if (strCommand == "smsgShow")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        printf("vchData.size() %d.\n", vchData.size());
        if (vchData.size() < 8)
            return false;
        
        int64_t time;
        memcpy(&time, &vchData[0], 8);
        // todo check time valid
        
        std::set<SecMsgToken>& tokenSet = smsgSets[time];
        std::set<SecMsgToken>::iterator it;
        
        std::vector<unsigned char> vchDataOut;
        vchDataOut.resize(8 + 16 * tokenSet.size());
        memcpy(&vchDataOut[0], &vchData[0], 8);
        
        
        
        unsigned char* p = &vchDataOut[8];
        for (it = tokenSet.begin(); it != tokenSet.end(); ++it)
        {
            //uint32_t size = it->second.size();
            
            memcpy(p, &it->timestamp, 8);
            memcpy(p+8, &it->sample, 8);
            
            p += 16;
        };
        pfrom->PushMessage("smsgHave", vchDataOut);
        
        
    } else
    if (strCommand == "smsgHave")
    {
        std::vector<unsigned char> vchData;
        vRecv >> vchData;
        printf("vchData.size() %d.\n", vchData.size());
        if (vchData.size() < 8)
            return false;
        
        int n = (vchData.size() - 8) / 16;
        
        int64_t time;
        memcpy(&time, &vchData[0], 8);
        // todo check time valid
        
        
        
        std::vector<unsigned char> vchDataOut;
        vchDataOut.resize(8);
        memcpy(&vchDataOut[0], &vchData[0], 8);
        
        std::set<SecMsgToken>& tokenSet = smsgSets[time];
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
        printf("vchData.size() %d.\n", vchData.size());
        if (vchData.size() < 8)
            return false;
        
        int n = (vchData.size() - 8) / 16;
        
        int64_t time;
        memcpy(&time, &vchData[0], 8);
        // todo check time valid
        
        std::set<SecMsgToken>& tokenSet = smsgSets[time];
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
                printf("Don't have message %ld.\n", token.timestamp);
            } else
            {
                printf("have message at %ld.\n", it->offset);
                token.offset = it->offset;
                SecureMsgTransmit(pfrom, token);
            }
            
            p += 16;
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
    //printf("SecureMsgSendData() %s.\n", pto->addrName.c_str());
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    int64_t now = time(NULL);
    
    
    if (pto->smsgData.lastSeen == 0)
    {
        // -- first contact
        //vector<char> vData;
        //vData.resize(strlen("enabled"));
        //memcpy(&vData[0], "enabled", strlen("enabled"));
        //pto->PushMessage("smsgQuery", "enabled");
        
        printf("SecureMsgSendData() new node %s.\n", pto->addrName.c_str());
        // Send smsgPing once, do nothing until receive 1st smsgPong (then set enabled)
        pto->PushMessage("smsgPing");
        pto->smsgData.lastSeen = time(NULL);
        return true;
    } else
    if (!pto->smsgData.enabled
        || now - pto->smsgData.lastSeen < 10)
    {
        return true;
    }
    
    
    //pto->PushMessage("smsgPing");
    
    {
        LOCK(cs_smsg);
        std::map<int64_t, std::set<SecMsgToken> >::iterator it;
        
        uint32_t nbuckets = smsgSets.size(); // uint16?
        
        
        std::vector<unsigned char> vchData;
        vchData.resize(4 + nbuckets*12);
        
        memcpy(&vchData[0], &nbuckets, 4);
        unsigned char* p = &vchData[4];
        for (it = smsgSets.begin(); it != smsgSets.end(); ++it)
        {
            uint32_t size = it->second.size();
            
            memcpy(p, &it->first, 8);
            memcpy(p+8, &size, 4);
            
            p += 12;
            //if (fDebug)
            //    printf("Sending bucket %ld, size %d \n", it->first, it->second.size());
        };
        printf("Sending %d buckets.\n", nbuckets);
        
        pto->PushMessage("smsgInv", vchData);
    }
    /*
    for (int i = 0; i < smsgSend.size(); ++i)
    {
        SecureMessage smsg;
        SecureMsgRetrieve(smsg, smsgSend[i].offset);
        // todo: retrieve directly into vch
        //printf("after SecureMsgRetrieve %d.\n", smsg.nPayload);
        
        std::vector<unsigned char> vchDuplicate;
        vchDuplicate.resize(SMSG_HDR_LEN + smsg.nPayload);
        
        memcpy(&vchDuplicate[0], &smsg.hash[0], SMSG_HDR_LEN);
        memcpy(&vchDuplicate[SMSG_HDR_LEN], smsg.pPayload, smsg.nPayload);
        
        pto->PushMessage("smsgMsg", vchDuplicate);
        
    };
    smsgSend.clear();
    */
    
    pto->smsgData.lastSeen = time(NULL);
    
    return true;
};



bool ScanChainForPublicKeys(CBlockIndex* pindexStart)
{
    printf("Scanning block chain for public keys.\n");
    
    printf("From height %u.\n", pindexStart->nHeight);
    
    // public keys are in txin.scriptSig
    // matching addresses are in scriptPubKey of txin's referenced output
    throw std::runtime_error("test throw");
    
    uint32_t nBlocks = 0;
    uint32_t nTransactions = 0;
    uint32_t nInputs = 0;
    uint32_t nPubkeys = 0;
    uint32_t nDuplicates = 0;
    
    CAddrToPubKeyDB addrpkdb("cw");
    CTxDB txdb("r");
    
    CBlockIndex* pindex = pindexStart;
    while (pindex)
    {
        nBlocks++;
        CBlock block;
        block.ReadFromDisk(pindex, true);
        BOOST_FOREACH(CTransaction& tx, block.vtx)
        {
            if (!tx.IsStandard())
                continue; // leave out coinbase and others
            
            /*
            Look at the inputs of every tx.
            If the inputs are standard, get the pubkey from scriptsig and uncompress it
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
                
                
                // matching address is in scriptPubKey of previous tx output
                while (pc < pend)
                {
                    if (!script->GetOp(pc, opcode, vch))
                        break;
                    // -- opcode is the length of the following data, compressed public key is always 33
                    if (opcode == 33)
                    {
                        //printf("Found Compressed public key %s.\n", ValueString(vch).c_str());
                        
                        //key.Reset();
                        key.SetPubKey(vch);
                        // EC_KEY_set_conv_form(key->k, POINT_CONVERSION_UNCOMPRESSED); // y^2 = x^3 + 7
                        key.SetUnCompressedPubKey();  // let openSSL recover Y coordinate
                        CPubKey uncPubKey = key.GetPubKey();
                        //printf("uncompressed public key %s.\n", ValueString(uncPubKey.Raw()).c_str());
                        
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
                        
                        if (addrpkdb.ExistsPK(hashKey))
                        {
                            /*
                            CPubKey cpkCheck;
                            if (!addrpkdb.ReadPK(hashKey, cpkCheck))
                            {
                                printf("addrpkdb.Read failed: %s.\n", coinAddress.ToString().c_str());
                                break;
                            };
                            printf("cpkCheck: %s.\n", ValueString(cpkCheck.Raw()).c_str());
                            if (cpkCheck != uncPubKey)
                            {
                                printf("cpkCheck != uncPubKey.\n");
                                break;
                            }
                            */
                            nDuplicates++;
                            break;
                        };
                        
                        if (!addrpkdb.WritePK(hashKey, uncPubKey))
                        {
                            printf("Write pair failed: %s.\n", coinAddress.ToString().c_str());
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
            
            if (nTransactions % 10000 == 0)
            {
                printf("Scanning transaction no. %u.\n", nTransactions);
            };
            
        };
        pindex = pindex->pnext;
    };
    
    addrpkdb.Close(); // necessary?
    
    printf("Scanned %u blocks, %u transactions, %u inputs\n", nBlocks, nTransactions, nInputs);
    printf("Found %u public keys, %u duplicates.\n", nPubkeys, nDuplicates);
    
    return true;
};

bool SecureMsgScanBlockChain()
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
    }
    return true;
};

int SecureMsgScanMessages()
{
    
    
    
    return 0;
};


int GetLocalPublicKey(std::string& strAddress, std::string& strPublicKey)
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
    
    //CBitcoinAddress testAddr;
    //testAddr.Set(keyID);
    
    CKey key;
    if (!pwalletMain->GetKey(keyID, key))
        return 4;
    
    key.SetUnCompressedPubKey();  // let openSSL recover Y coordinate
    CPubKey pubKey = key.GetPubKey();
    printf("public key %s.\n", ValueString(pubKey.Raw()).c_str());
    strPublicKey = EncodeBase58(pubKey.Raw());
    
    //std::string keyb58 = EncodeBase58(pubKey.Raw());
    //printf("keyb58 %s.\n", keyb58.c_str());
    return 0;
};

int GetStoredKey(CKeyID& ckid, CPubKey& cpkOut)
{
    /* returns
        0 success,
        1 error
        2 public key not in database
    */
    if (fDebug)
        printf("GetStoredKey().\n");
    
    CAddrToPubKeyDB addrpkdb("r");
    
    if (!addrpkdb.ReadPK(ckid, cpkOut))
    {
        //printf("addrpkdb.Read failed: %s.\n", coinAddress.ToString().c_str());
        return 2;
    };
    printf("cpkOut: %s.\n", ValueString(cpkOut.Raw()).c_str());
    
    addrpkdb.Close(); // necessary?
    
    return 0;
};

int SecureMsgInsertAddress(CKeyID& hashKey, CPubKey& pubKey)
{
    /* insert key hash and public key to addressdb
        
        returns
            0 success
            4 address is already in db
            5 error
    */
    
    CAddrToPubKeyDB addrpkdb("cr+");
    
    if (addrpkdb.ExistsPK(hashKey))
    {
        //printf("DB already contains public key for address: %s.\n", coinAddress.ToString().c_str());
        printf("DB already contains public key for address.\n");
        CPubKey cpkCheck;
        if (!addrpkdb.ReadPK(hashKey, cpkCheck))
        {
            printf("addrpkdb.Read failed.\n");
        } else
        {
            //printf("cpkCheck: %s.\n", ValueString(cpkCheck.Raw()).c_str());
            //printf("pubKey: %s.\n", ValueString(pubKey.Raw()).c_str());
            if (cpkCheck != pubKey)
                printf("Existing public key does not match .\n");
        };
        return 4;
    };
    
    if (!addrpkdb.WritePK(hashKey, pubKey))
    {
        printf("Write pair failed.\n");
        return 5;
    };
    
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
    printf("addressT %s.\n", addressT.ToString().c_str());
    
    if (addressT.ToString().compare(address) != 0)
    {
        printf("Public key does not hash to address, addressT %s.\n", addressT.ToString().c_str());
        return 3;
    };
    
    return SecureMsgInsertAddress(hashKey, pubKey);
};

int SecureMsgTransmit(CNode* pto, SecMsgToken &token)
{
    if (fDebug)
        printf("SecureMsgTransmit().\n");
    
    // -- has cs_smsg lock from SecureMsgReceiveData
    
    std::vector<unsigned char> vchData;
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    
    int64_t bucket = token.timestamp - (token.timestamp % SMSG_BUCKET_LEN);
    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    
    fs::path fullpath = pathSmsgDir / fileName;
    
    printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    FILE *fp;
    if (!(fp = fopen(fullpath.string().c_str(), "r")))
    {
        printf("Error opening file: %s\n", strerror(errno));
        return 1;
    };
    
    printf("token.offset: %ld\n", token.offset);
    
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
    
    pto->PushMessage("smsgMsg", vchData);
    
    return 0;
};

int SecureMsgReceive(std::vector<unsigned char>& vchData)
{
    if (fDebug)
        printf("SecureMsgReceive().\n");
    
    // todo handle multiple messages
    // save directly from vchData
    
    SecureMessage smsg;
    
    
    memcpy(&smsg.hash[0], &vchData[0], SMSG_HDR_LEN);
    printf("smsg.nPayload %d.\n",smsg.nPayload);
    
    try {
        smsg.pPayload = new unsigned char[smsg.nPayload];
    } catch (std::exception& e)
    {
        printf("Could not allocate pPayload, exception: %s.\n", e.what());
        return false;
    };

    memcpy(smsg.pPayload, &vchData[SMSG_HDR_LEN], smsg.nPayload);
    
    if (SecureMsgStore(smsg) != 0)
    {
        // message dropped
        return 1;
    };
    
    
    // Todo move this elsewhere, ScanSecureMessage/s()
    
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& entry, pwalletMain->mapAddressBook)
    {
        if (!IsMine(*pwalletMain, entry.first))
            continue;
        
        //printf("entry.first %s.\n", entry.first.ToString.c_str());
        CBitcoinAddress coinAddress(entry.first);
        printf("coinAddress: %s.\n", coinAddress.ToString().c_str());
        
        std::string addressTo = coinAddress.ToString();
        printf("addressTo: %s.\n", addressTo.c_str());
        
        MessageData msg;
        if (SecureMsgDecrypt(addressTo, smsg, msg) == 0)
        {
            printf("Decrypted message!\n");
            break;
        };
    };
    
    
    return 0;
};

int SecureMsgStore(SecureMessage& smsg)
{
    if (fDebug)
        printf("SecureMsgStore()\n");
    
    long int ofs;
    
    fs::path pathSmsgDir = GetDataDir() / "smsgStore";
    fs::create_directory(pathSmsgDir);
    
    int64_t now = GetTime();
    if (smsg.timestamp > now)
    {
        printf("Message > now\n");
        return 1;
    } else
    if (smsg.timestamp < now - SMSG_RETENTION)
    {
        printf("Message < SMSG_RETENTION\n");
        return 1;
    };
    
    int64_t bucket = smsg.timestamp - (smsg.timestamp % SMSG_BUCKET_LEN);
    std::string fileName = boost::lexical_cast<std::string>(bucket) + "_01.dat";
    
    fs::path fullpath = pathSmsgDir / fileName;
    
    printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    {
        // -- must lock cs_smsg before calling
        //LOCK(cs_smsg);
        
        SecMsgToken token(smsg.timestamp, smsg.pPayload, smsg.nPayload, 0);
        
        std::set<SecMsgToken>::iterator it;
        it = smsgSets[bucket].find(token);
        if (it != smsgSets[bucket].end())
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
        
        if (fwrite(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN
            || fwrite(smsg.pPayload, sizeof(unsigned char), smsg.nPayload, fp) != smsg.nPayload)
        {
            printf("fwrite failed: %s\n", strerror(errno));
            fclose(fp);
            return 1;
        };
        
        token.offset = ofs;
        //unsigned char hash[4];
        //smsgStored.push_back();
        //smsgSend.push_back(SecMsgLocation(smsg.timestamp, hash, ofs));
        
        fclose(fp);
        
        smsgSets[bucket].insert(token);
    };
    
    
    return 0;
};

int SecureMsgRetrieve(SecureMessage& smsg, long int offset)
{
    // REMOVE: ever needed?
    if (fDebug)
        printf("SecureMsgRetrieve()\n");
    
    
    boost::filesystem::path fullpath = GetDataDir() / "smsgStore/01.dat";
    
    printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    {
        // has cs_smsg lock from SecureMsgReceiveData
        //LOCK(cs_smsg);
        
        FILE *fp;
        
        if (!(fp = fopen(fullpath.string().c_str(), "r")))
        {
            printf("Error opening file: %s\n", strerror(errno));
            return 1;
        };
        
        //long int ofs = ftell(fp);
        
        if (fseek(fp, offset, SEEK_SET) != 0)
        {
            printf("fseek, strerror: %s.\n", strerror(errno));
            fclose(fp);
            return 1;
        }
        
        if (fread(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != (size_t)SMSG_HDR_LEN)
        {
            printf("fread header failed: %s\n", strerror(errno));
            fclose(fp);
            return 1;
        };
        
        printf("smsg.nPayload %d\n", smsg.nPayload);
        try {
            smsg.pPayload = new unsigned char[smsg.nPayload];
        } catch (std::exception& e)
        {
            printf("Could not allocate pPayload, exception: %s.\n", e.what());
            fclose(fp);
            return 1;
        };
        
        if (fread(smsg.pPayload, sizeof(unsigned char), smsg.nPayload, fp) != smsg.nPayload)
        {
            printf("fread data failed: %s\n", strerror(errno));
            fclose(fp);
            return 1;
        };
        
        
        fclose(fp);
    };
    
    return 0;
};

int SecureMsgSend(std::string& addressFrom, std::string& addressTo, std::string& message)
{
    // -- create a secure message, and place it on the network
    
    /*
        Using the same method as bitmessage.
        If bitmessage is secure this should be too.
        https://bitmessage.org/wiki/Encryption
        
        Some differences:
        bitmessage seems to use curve sect283r1
        Cinnicoin addresses use secp256k1
        
    */
    
    if (fDebug)
        printf("SecureMsgSend(%s, %s, ...)\n", addressFrom.c_str(), addressTo.c_str());
    
    
    
    SecureMessage secMesg;
    secMesg.version = 1;
    secMesg.timestamp = time(NULL);
    
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
            return 1;
        };
        
        if (!coinAddrFrom.GetKeyID(ckidFrom))
        {
            printf("coinAddrFrom.GetKeyID failed: %s.\n", coinAddrFrom.ToString().c_str());
            return 1;
        };
    };
    
    
    CBitcoinAddress coinAddrDest;
    CKeyID ckidDest;
    
    if (!coinAddrDest.SetString(addressTo))
    {
        printf("addressTo is not valid.\n");
        return 1;
    };
    
    //printf("coinAddrDest: %s.\n", coinAddrDest.ToString().c_str());
    if (!coinAddrDest.GetKeyID(ckidDest))
    {
        printf("coinAddrDest.GetKeyID failed: %s.\n", coinAddrDest.ToString().c_str());
        return 1;
    };
    
    // -- public key K is the destination address
    CPubKey cpkDestK;
    if (GetStoredKey(ckidDest, cpkDestK) != 0)
    {
        printf("Could not get public key for destination address.\n");
        return 1;
    };
    
    
    // -- Generate 16 random bytes using a secure random number generator. Call them IV.
    
    RandAddSeedPerfmon();
    
    RAND_bytes(&secMesg.iv[0], 16);
    
    
    // -- Generate a new random EC key pair with private key called r and public key called R.
    
    CKey keyR;
    keyR.MakeNewKey(false); // make uncompressed key
    
    // -- Do an EC point multiply with public key K and private key r. This gives you public key P. 
    
    //printf("cpkK: %s.\n", ValueString(cpkK.Raw()).c_str());
    CKey keyK;
    keyK.SetUnCompressedPubKey();
    if (!keyK.SetPubKey(cpkDestK))
    {
        printf("Could not set pubkey for K: %s.\n", ValueString(cpkDestK.Raw()).c_str());
        return 1;
    };
    
    std::vector<unsigned char> vch;
    vch.resize(32);
    EC_KEY* pkeyr = keyR.GetECKey();
    EC_KEY* pkeyK = keyK.GetECKey();
    
    // always seems to be 32, worth checking?
    //int field_size = EC_GROUP_get_degree(EC_KEY_get0_group(pkeyr));
    //int secret_len = (field_size+7)/8;
    //printf("secret_len %d.\n", secret_len);
    
    ECDH_set_method(pkeyr, ECDH_OpenSSL());
    int lenP = ECDH_compute_key(&vch[0], 32, EC_KEY_get0_public_key(pkeyK), pkeyr, NULL);
    
    if (lenP != 32)
    {
        printf("ECDH_compute_key failed, lenP: %d.\n", lenP);
        return 1;
    };
    
    // Compress pubkey R to save bytes
    keyR.SetCompressedPubKey();
    CPubKey cpkR = keyR.GetPubKey();
    if (!cpkR.IsValid()
        || !cpkR.IsCompressed())
    {
        printf("Could not get public key for key R.\n");
        return 1;
    }
    //printf("cpkR.Raw().size() %d.\n", cpkR.Raw().size());
    //printf("compressed cpkR %s.\n", ValueString(cpkR.Raw()).c_str());
    memcpy(secMesg.cpkR, &cpkR.Raw()[0], 33);
    
    printf("lenP: %d.\n", lenP);
    printf("P: %s.\n", ValueString(vch).c_str());
    
    
    // -- Use public key P and calculate the SHA512 hash H. 
    
    std::vector<unsigned char> vchHashed;
    vchHashed.resize(64); // 512
    
    // X component where?, is ECDH_compute_key returning a compressed key? could be as it's only 32 bytes
    SHA512(&vch[0], vch.size(), (unsigned char*)&vchHashed[0]);
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
    printf("lenMsg: %d.\n", lenMsg);
    if (lenMsg > 128)
    {
        // only compress if over 128 bytes
        int worstCase = LZ4_compressBound(message.size());
        printf("worstCase: %d.\n", worstCase);
        vchCompressed.resize(worstCase);
        int lenComp = LZ4_compress((char*)message.c_str(), (char*)&vchCompressed[0], lenMsg);
        printf("lenComp: %d.\n", lenComp);
        if (lenComp < 1)
        {
            printf("Could not compress message data.\n");
            return 1;
        };
        pMsgData = &vchCompressed[0];
        lenMsgData = lenComp;
        
    } else
    {
        pMsgData = (unsigned char*)message.c_str();
        lenMsgData = lenMsg;
        //vchPayload.resize(SMSG_PL_HDR_LEN + lenMsg);
        //memcpy(&vchPayload[SMSG_PL_HDR_LEN], message.c_str(), lenMsg);
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
            return 4;
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
    crypter.SetKey(key_e, secMesg.iv);
    std::vector<unsigned char> vchCiphertext;
    
    if (!crypter.Encrypt(&vchPayload[0], vchPayload.size(), vchCiphertext))
        printf("crypter.Encrypt failed.\n");
    
    try {
        secMesg.pPayload = new unsigned char[vchCiphertext.size()];
    } catch (std::exception& e)
    {
        printf("Could not allocate pPayload, exception: %s.\n", e.what());
        return 1;
    };
    
    memcpy(secMesg.pPayload, &vchCiphertext[0], vchCiphertext.size());
    
    secMesg.nPayload = vchCiphertext.size();
    
    
    // Calculate a 32 byte MAC with HMACSHA256, using key_m as salt
    // Message authentication code, (hash of timestamp + destination + IV + payload)
    
    bool fHmacOk = true;
    unsigned int nBytes = 32;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    
    if (!HMAC_Init_ex(&ctx, &key_m[0], 32, EVP_sha256(), NULL)
        || !HMAC_Update(&ctx, (unsigned char*) &secMesg.timestamp, sizeof(secMesg.timestamp))
        || !HMAC_Update(&ctx, (unsigned char*) &secMesg.destHash[0], sizeof(secMesg.destHash))
        || !HMAC_Update(&ctx, &vchCiphertext[0], vchCiphertext.size())
        || !HMAC_Final(&ctx, secMesg.mac, &nBytes)
        || nBytes != 32)
        fHmacOk = false;
    
    HMAC_CTX_cleanup(&ctx);
    
    if (!fHmacOk)
    {
        printf("Could not generate MAC.\n");
        return 1;
    };
    
    // todo hash checksum
    
    // todo save random key, to allow outgoing messages to be read.
    //   or create a copy 'sent' to an owned address that isn't broadcast
    
    // -- add to message store
    
    {
        LOCK(cs_smsg);
        SecureMsgStore(secMesg);
        //smsgStore.push(secMesg);
    }
    
    if (fDebug)
        printf("Secure message sent to %s.\n", addressTo.c_str());
    
    //MessageData msg;
    //SecureMsgDecrypt(addressTo, secMesg, msg);
    
    return 0;
};

int SecureMsgDecrypt(std::string& address, SecureMessage& smsg, MessageData& msg)
{
    if (fDebug)
        printf("SecureMsgDecrypt(), using %s.\n", address.c_str());
    
    // -- address is the owned address to decrypt with.
    
    
    // TODO validate SecureMessage, check hash, nPayload, etc
    
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
    std::vector<unsigned char> vchR(smsg.cpkR, smsg.cpkR+33); // would be neater to override CPubKey() instead
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
    keyR.SetUnCompressedPubKey();
    cpkR = keyR.GetPubKey();
    if (!cpkR.IsValid()
        || cpkR.IsCompressed())
    {
        printf("Could not get uncompressed public key for key R.\n");
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
    
    // Use public key P to calculate the SHA512 hash H. 
    
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
        || !HMAC_Update(&ctx, (unsigned char*) &smsg.timestamp, sizeof(smsg.timestamp))
        || !HMAC_Update(&ctx, (unsigned char*) &smsg.destHash[0], sizeof(smsg.destHash))
        || !HMAC_Update(&ctx, smsg.pPayload, smsg.nPayload)
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
    if (memcmp(MAC, smsg.mac, 32) != 0)
    {
        printf("MAC does not match.\n");
        return 1;
    };
    
    SMsgCrypter crypter;
    crypter.SetKey(key_e, smsg.iv);
    std::vector<unsigned char> vchPayload;
    if (!crypter.Decrypt(smsg.pPayload, smsg.nPayload, vchPayload))
    {
        printf("Decrypt failed.\n");
        return 1;
    };
    
    msg.timestamp = smsg.timestamp;
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
    printf("msg.vchMessage %s.\n", &msg.vchMessage[0]);
    
    if (fFromAnonymous)
    {
        printf("Anonymous sender.\n");
        
        std::string sender = "anon";
        
        msg.vchFromAddress.resize(sender.size());
        memcpy(&msg.vchFromAddress[0], sender.c_str(), sender.size());
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
        printf("coinAddrFrom %s.\n", coinAddrFrom.ToString().c_str());
        
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
        
        // Need the full public key here
        keyFrom.SetUnCompressedPubKey();
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
        
        printf("coinAddrFrom %s.\n", coinAddrFrom.ToString().c_str());
        
        std::string sender = coinAddrFrom.ToString();
        msg.vchFromAddress.resize(sender.size());
        memcpy(&msg.vchFromAddress[0], sender.c_str(), sender.size());
    };
    
    if (fDebug)
        printf("Decrypted message for %s.\n", address.c_str());
    
    return 0;
};
