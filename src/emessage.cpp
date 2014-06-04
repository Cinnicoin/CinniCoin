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



#include "base58.h"
#include "db.h"
#include "init.h" // pwalletMain

#include "lz4/lz4.h"
#include "lz4/lz4.c"


//std::map<std::string, SecMsgNode*> smsgNodeData;

//std::vector<SecureMessage> smsgStore; // temporary

//std::vector<SecureMessage*> smsgUnsent;



std::vector<SecMsgLocation> smsgSend; // temporary

std::vector<SecMsgLocation> smsgStored; // move to db?



CCriticalSection cs_smsg;


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



/** called from AppInit2() in init.cpp */
bool SecureMsgStart()
{
    printf("Starting secure messaging.\n");
    
    
    
    
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
        
        // todo proper recieve function
        std::vector<unsigned char> vchDuplicate;
        vRecv >> vchDuplicate;
        printf("vchDuplicate.size() %d.\n",vchDuplicate.size());
        
        SecureMessage smsg;
        
        memcpy(&smsg.hash[0], &vchDuplicate[0], SMSG_HDR_LEN);
        printf("smsg.nPayload %d.\n",smsg.nPayload);
        
        try {
            smsg.pPayload = new unsigned char[smsg.nPayload];
        } catch (std::exception& e)
        {
            printf("Could not allocate pPayload, exception: %s.\n", e.what());
            return false;
        };

        memcpy(smsg.pPayload, &vchDuplicate[SMSG_HDR_LEN], smsg.nPayload);
        
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
        
        
    } else
    {
        // Unknown message
    }
    
    
    return true;
};

bool SecureMsgSendData(CNode* pto, bool fSendTrickle)
{
    //printf("SecureMsgSendData() %s.\n", pto->addrName.c_str());
    /*
        Called from ProcessMessage
        Runs in ThreadMessageHandler2
    */
    
    uint64_t now = time(NULL);
    
    
    
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
    
    
    pto->PushMessage("smsgPing");
    
    
    
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

int SecureMsgStore(SecureMessage& smsg)
{
    if (fDebug)
        printf("SecureMsgStore()\n");
    
    
    boost::filesystem::path pathSmsgDir = GetDataDir() / "smsgStore";
    boost::filesystem::create_directory(pathSmsgDir);
    
    boost::filesystem::path fullpath = pathSmsgDir / "01.dat";
    
    printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    {
        LOCK(cs_smsg);
        FILE *fp;
        
        if (!(fp = fopen(fullpath.string().c_str(), "a")))
        {
            printf("Error opening file: %s\n", strerror(errno));
            return 1;
        };
        
        
        long int ofs = ftell(fp);
        
        if (fwrite(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != SMSG_HDR_LEN
            || fwrite(smsg.pPayload, sizeof(unsigned char), smsg.nPayload, fp) != smsg.nPayload)
        {
            printf("fwrite failed: %s\n", strerror(errno));
            fclose(fp);
            return 1;
        };
        
        unsigned char hash[4];
        //smsgStored.push_back();
        smsgSend.push_back(SecMsgLocation(smsg.timestamp, hash, ofs));
        
        fclose(fp);
    };
    
    return 0;
};

int SecureMsgRetrieve(SecureMessage& smsg, long int offset)
{
    if (fDebug)
        printf("SecureMsgRetrieve()\n");
    
    
    boost::filesystem::path fullpath = GetDataDir() / "smsgStore/01.dat";
    
    printf("fullpath.string().c_str() %s.\n", fullpath.string().c_str());
    
    {
        LOCK(cs_smsg);
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
        
        if (fread(&smsg.hash[0], sizeof(unsigned char), SMSG_HDR_LEN, fp) != SMSG_HDR_LEN)
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
    
    CBitcoinAddress coinAddrFrom;
    if (!coinAddrFrom.SetString(addressFrom))
    {
        printf("addressFrom is not valid.\n");
        return 1;
    }
    
    //printf("coinAddrDest: %s.\n", coinAddrDest.ToString().c_str());
    CKeyID ckidFrom;
    if (!coinAddrFrom.GetKeyID(ckidFrom))
    {
        printf("coinAddrFrom.GetKeyID failed: %s.\n", coinAddrFrom.ToString().c_str());
        return 1;
    };
    
    CBitcoinAddress coinAddrDest;
    if (!coinAddrDest.SetString(addressTo))
    {
        printf("addressTo is not valid.\n");
        return 1;
    }
    
    //printf("coinAddrDest: %s.\n", coinAddrDest.ToString().c_str());
    CKeyID ckidDest;
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
    
    
    // -- Use the X component of public key P and calculate the SHA512 hash H. 
    
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
    
    
    
    // -- compact signature allows the public key to be recovered, recipient can always reply!
    
    CKey keyFrom;
    if (!pwalletMain->GetKey(ckidFrom, keyFrom))
    {
        printf("Could not get private key for addressFrom.\n");
        return 4;
    };
    
    std::vector<unsigned char> vchSignature;
    vchSignature.resize(65);
    keyFrom.SignCompact(Hash(message.begin(), message.end()), vchSignature);
    
    
    std::vector<unsigned char> vchPayload;
    
    uint32_t lenMsg = message.size();
    
    printf("lenMsg: %d.\n", lenMsg);
    if (lenMsg > 128)
    {
        // only compress if over 128 bytes
        std::vector<unsigned char> vchCompressed;
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
        vchPayload.resize(1 + 20 + 65 + 4 + lenComp);
        memcpy(&vchPayload[1+20+65+4], &vchCompressed[0], lenComp);
    } else
    {
        vchPayload.resize(1 + 20 + 65 + 4 + lenMsg);
        memcpy(&vchPayload[1+20+65+4], message.c_str(), lenMsg);
    };
    
    // Save some bytes by sending address raw
    vchPayload[0] = (static_cast<CBitcoinAddress_B*>(&coinAddrFrom))->getVersion(); // vchPayload[0] = coinAddrDest.nVersion;
    memcpy(&vchPayload[1], (static_cast<CKeyID_B*>(&ckidFrom))->GetPPN(), 20); // memcpy(&vchPayload[1], ckidDest.pn, 20);
    
    memcpy(&vchPayload[1+20], &vchSignature[0], vchSignature.size());
    memcpy(&vchPayload[1+20+65], &lenMsg, 4);
    
    //printf("message: %s.\n", message.c_str());
    
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
    
    // todo checksum
    
    // todo save random key, to allow outgoing messages to be read.
    
    
    // -- add to message store
    
    SecureMsgStore(secMesg);
    //smsgStore.push(secMesg);
    
    
    
    if (fDebug)
        printf("Secure message sent to %s.\n", addressTo.c_str());
    
    MessageData msg;
    SecureMsgDecrypt(addressTo, secMesg, msg);
    
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
    }
    
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
    }
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
    }
    
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
    
    // Use the X component of shared public key P and calculate the SHA512 hash H. 
    
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
    uint32_t lenData = vchPayload.size() - (1+20+65+4);
    uint32_t lenPlain;
    memcpy(&lenPlain, &vchPayload[1+20+65], 4);
    
    msg.vchMessage.resize(lenPlain + 1);
    
    if (lenPlain > 128)
    {
        // decompress
        
        if (LZ4_decompress_safe((char*) &vchPayload[1+20+65+4], (char*) &msg.vchMessage[0], lenData, lenPlain) != (int) lenPlain)
        {
            printf("Could not decompress message data.\n");
            return 1;
        };
    } else
    {
        // plaintext
        memcpy(&msg.vchMessage[0], &vchPayload[1+20+65+4], lenPlain);
    }
    
    msg.vchMessage[lenPlain] = '\0';
    printf("msg.vchMessage %s.\n", &msg.vchMessage[0]);
    
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
    //msg.vchFromAddress
    
    std::vector<unsigned char> vchSig;
    vchSig.resize(65);
    
    memcpy(&vchSig[0], &vchPayload[1+20], 65);
    
    CKey keyFrom;
    keyFrom.SetCompactSignature(Hash(vchPayload.begin()+1+20+65+4, vchPayload.end()), vchSig);
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
    
    int rv;
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
    
    
    if (fDebug)
        printf("Decrypted message for %s.\n", address.c_str());
    
    return 0;
};
