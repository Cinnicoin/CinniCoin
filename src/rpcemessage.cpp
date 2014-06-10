// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
    Link in bitcoinrpc.h/cpp
*/


// #include <unordered_set>

#include "main.h"
#include "bitcoinrpc.h"

#include <boost/lexical_cast.hpp>

#include "emessage.h"
#include "init.h" // pwalletMain

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

Value smsgscanchain(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanchain \n"
            "Look for public keys in the block chain.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    Object result;
    if (!SecureMsgScanBlockChain())
    {
        result.push_back(Pair("result", "Scan Failed."));
    } else
    {
        result.push_back(Pair("result", "Scan Completed."));
    }
    return result;
}

Value smsgaddkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgaddkey <address> <pubkey>\n"
            "Add address, pubkey pair to database.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addr = params[0].get_str();
    std::string pubk = params[1].get_str();
    
    Object result;
    
    if (SecureMsgAddAddress(addr, pubk) != 0)
        result.push_back(Pair("result", "Public key not added to db."));
    else
        result.push_back(Pair("result", "Added public key to db."));
    
    return result;
}

Value smsggetpubkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "smsggetpubkey <address>\n"
            "Return the base58 encoded compressed public key for an address.\n"
            "Tests localkeys first, then looks in public key db.\n");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    
    std::string address   = params[0].get_str();
    std::string publicKey;
    
    Object result;
    int rv = SecureMsgGetLocalPublicKey(address, publicKey);
    switch (rv)
    {
        case 0:
            result.push_back(Pair("result", "Success."));
            result.push_back(Pair("address in wallet", address));
            result.push_back(Pair("compressed public key", publicKey));
            return result; // success, don't check db
        case 2:
        case 3:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Invalid address."));
            return result;
        case 4:
            //result.push_back(Pair("result", "Failed."));
            //result.push_back(Pair("message", "Address not found in wallet."));
            break; // check db
        //case 1:
        default:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Error."));
            return result;
    };
    
    CBitcoinAddress coinAddress(address);
    
    
    CKeyID keyID;
    if (!coinAddress.GetKeyID(keyID))
    {
        result.push_back(Pair("result", "Failed."));
        result.push_back(Pair("message", "Invalid address."));
        return result;
    };
    
    CPubKey cpkFromDB;
    rv = SecureMsgGetStoredKey(keyID, cpkFromDB);
    
    switch (rv)
    {
        case 0:
            if (!cpkFromDB.IsValid()
                || !cpkFromDB.IsCompressed())
            {
                result.push_back(Pair("result", "Failed."));
                result.push_back(Pair("message", "Invalid address."));
            } else
            {
                //cpkFromDB.SetCompressedPubKey(); // make sure key is compressed
                publicKey = EncodeBase58(cpkFromDB.Raw());
                
                result.push_back(Pair("result", "Success."));
                result.push_back(Pair("peer address in DB", address));
                result.push_back(Pair("compressed public key", publicKey));
            };
            break;
        case 2:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Address not found in wallet or db."));
            return result;
        //case 1:
        default:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Error, GetStoredKey()."));
            return result;
    };
    
    return result;
}

Value smsglistlocalkeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsglistlocalkeys\n"
            "List local addresses and public keys that this node can receive on.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    Object result;
    
    // TODO: whitelist of addresses to receive on
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& entry, pwalletMain->mapAddressBook)
    {
        if (!IsMine(*pwalletMain, entry.first))
            continue;
        
        
        //printf("entry.first %s.\n", entry.first.ToString.c_str());
        CBitcoinAddress coinAddress(entry.first);
        if (!coinAddress.IsValid())
            continue;
        
        std::string address;
        std::string strPublicKey;
        address = coinAddress.ToString();
        //result.push_back(Pair("result", Pair(address, "key.")));
        
        
        CKeyID keyID;
        if (!coinAddress.GetKeyID(keyID))
            continue;
        
        CKey key;
        if (!pwalletMain->GetKey(keyID, key))
            continue;
        
        key.SetCompressedPubKey(); // make sure key is compressed
        
        CPubKey pubKey = key.GetPubKey();
        if (!pubKey.IsValid()
            || !pubKey.IsCompressed())
        {
            continue;
        };
        
        
        //printf("public key %s.\n", ValueString(pubKey.Raw()).c_str());
        strPublicKey = EncodeBase58(pubKey.Raw());
        
        result.push_back(Pair("result", address + " - " + strPublicKey));
        
    };
    
    return result;
};

Value smsgsend(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "smsgsend <addrFrom> <addrTo> <message>\n"
            "Send an encrypted message from addrFrom to addrTo.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addrFrom  = params[0].get_str();
    std::string addrTo    = params[1].get_str();
    std::string msg       = params[2].get_str();
    
    
    Object result;
    
    if (SecureMsgSend(addrFrom, addrTo, msg) != 0)
        result.push_back(Pair("result", "Send failed."));
    else
        result.push_back(Pair("result", "Sent."));

    return result;
}

Value smsgsendanon(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgsendanon <addrTo> <message>\n"
            "Send an anonymous encrypted message to addrTo.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addrFrom  = "anon";
    std::string addrTo    = params[0].get_str();
    std::string msg       = params[1].get_str();
    
    
    Object result;
    
    if (SecureMsgSend(addrFrom, addrTo, msg) != 0)
        result.push_back(Pair("result", "Send failed."));
    else
        result.push_back(Pair("result", "Sent."));

    return result;
}

Value smsginbox(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // defaults to read
        throw runtime_error(
            "smsginbox [all|unread|clear]\n" 
            "Decrypt and display all received messages.\n"
            "Warning: clear will delete all messages.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string mode = "unread";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    }
    
    
    Object result;
    
    std::vector<unsigned char> vchUnread;
    std::vector<unsigned char> vchKey;
    vchKey.resize(16);
    memset(&vchKey[0], 0, 16);
    
    {
        LOCK(cs_smsgInbox);
        
        CSmesgInboxDB dbInbox("cr+");
        
        char cbuf[256];
        
        if (mode == "clear")
        {
            //result.push_back(Pair("result", "Clear not implemented yet."));
            
            Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get inbox DB cursor");
            
            uint32_t nMessages = 0;
            
            std::set<std::vector<unsigned char> > setToDelete;
            std::set<std::vector<unsigned char> >::iterator itd;
            
            Dbt datKey;
            Dbt datValue;
            
            datKey.set_flags(DB_DBT_USERMEM);
            datValue.set_flags(DB_DBT_USERMEM);
            
            std::vector<unsigned char> vchDelete;
            std::vector<unsigned char> vchKeyData;
            std::vector<unsigned char> vchValueData;
            
            vchKeyData.resize(100);
            vchValueData.resize(100);
            
            datKey.set_ulen(vchKeyData.size());
            datKey.set_data(&vchKeyData[0]);
            
            datValue.set_ulen(vchValueData.size());
            datValue.set_data(&vchValueData[0]);
            
            unsigned int fFlags = DB_NEXT; // same as using DB_FIRST for new cursor
            while (true)
            {
                int ret = pcursor->get(&datKey, &datValue, fFlags);
                
                if (ret == ENOMEM
                    || ret == DB_BUFFER_SMALL)
                {
                    if (datKey.get_size() > datKey.get_ulen())
                    {
                        //printf("Resizing vchKeyData %d\n", datKey.get_size());
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
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s\n", ret, db_strerror(ret));
                    throw runtime_error(cbuf);
                };
                
                if (datKey.get_size() != 17)
                    continue; // not a message key
                
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datKey.get_data(), datKey.get_size());
                ssValue >> vchKey;
                
                setToDelete.insert(vchKey);
                
                /*
                // TODO: how to be sure data is really gone?
                if ((ret = pcursor->del(0)) != 0) // NOT working
                {
                    printf("Delete failed %d, %s\n", ret, db_strerror(ret));
                };
                */
                nMessages++;
            };
            pcursor->close();
            
            for (itd = setToDelete.begin(); itd != setToDelete.end(); ++itd)
            {
                std::vector<unsigned char> vchDeleteT = (*itd);
                dbInbox.EraseSmesg(vchDeleteT);
            };
            
            
            vchUnread.resize(0);
            dbInbox.WriteUnread(vchUnread);
            
            
            snprintf(cbuf, sizeof(cbuf), "Deleted %u messages.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
            
        } else
        if (mode == "unread")
        {
            SecInboxMsg smsgInbox;

            //dbInbox.WriteSmesg(vchKey, vchData);
            
            dbInbox.ReadUnread(vchUnread);
            
            //result.push_back(Pair("unread", ValueString(vchUnread).c_str()));
            
            size_t nMessages = vchUnread.size() / 16;
            
            if (nMessages == 0)
            {
                result.push_back(Pair("result", "No unread messages."));
            } else
            {
                for (uint32_t i = 0; i < nMessages; ++i)
                {
                    memcpy(&vchKey[0], &vchUnread[i*16], 16);
                    
                    dbInbox.ReadSmesg(vchKey, smsgInbox);
                    
                    MessageData msg;
                    
                    uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
                    if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                    {
                        Object objM;
                        objM.push_back(Pair("received", getTimeString(smsgInbox.timeReceived, cbuf, sizeof(cbuf))));
                        objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                        objM.push_back(Pair("from", msg.sFromAddress));
                        objM.push_back(Pair("to", smsgInbox.sAddrTo));
                        objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0]))); // ugh
                        
                        result.push_back(Pair("message", objM));
                    } else
                    {
                        result.push_back(Pair("message", "Could not decrypt."));
                    };
                };
                
                snprintf(cbuf, sizeof(cbuf), "%lu unread messages shown.", nMessages);
                result.push_back(Pair("result", std::string(cbuf)));
                vchUnread.resize(0);
                dbInbox.WriteUnread(vchUnread);
            };
        } else
        if (mode == "all")
        {
            Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get inbox DB cursor");
            
            
            uint32_t nMessages = 0;
            
            Dbt datKey;
            Dbt datValue;
            
            datKey.set_flags(DB_DBT_USERMEM);
            datValue.set_flags(DB_DBT_USERMEM);
            
            std::vector<unsigned char> vchKeyData;
            std::vector<unsigned char> vchValueData;
            
            vchKeyData.resize(100);
            vchValueData.resize(100);
            
            datKey.set_ulen(vchKeyData.size());
            datKey.set_data(&vchKeyData[0]);
            
            datValue.set_ulen(vchValueData.size());
            datValue.set_data(&vchValueData[0]);
            
            unsigned int fFlags = DB_NEXT; // same as using DB_FIRST for new cursor
            while (true)
            {
                int ret = pcursor->get(&datKey, &datValue, fFlags);
                
                if (ret == ENOMEM
                    || ret == DB_BUFFER_SMALL)
                {
                    if (datKey.get_size() > datKey.get_ulen())
                    {
                        //printf("Resizing vchKeyData %d\n", datKey.get_size());
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
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s\n", ret, db_strerror(ret));
                    throw runtime_error(cbuf);
                };
                
                if (datKey.get_size() != 17)
                    continue; // not a message key
                
                nMessages++;
                // must be a better way?
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datValue.get_data(), datValue.get_size());
                SecInboxMsg smsgInbox;
                ssValue >> smsgInbox;
                
                MessageData msg;
                
                uint32_t nPayload = smsgInbox.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgInbox.sAddrTo, &smsgInbox.vchMessage[0], &smsgInbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {
                    Object objM;
                    objM.push_back(Pair("received", getTimeString(smsgInbox.timeReceived, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("from", msg.sFromAddress));
                    objM.push_back(Pair("to", smsgInbox.sAddrTo));
                    objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0]))); // ugh
                    
                    result.push_back(Pair("message", objM));
                } else
                {
                    result.push_back(Pair("message", "Could not decrypt."));
                };
            };

            pcursor->close();
            
            snprintf(cbuf, sizeof(cbuf), "%u messages shown.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
            
            
        } else
        {
            result.push_back(Pair("result", "Unknown Mode."));
            result.push_back(Pair("expected", "[all|unread|clear]."));
        };
    }
    
    return result;
};

Value smsgoutbox(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // defaults to read
        throw runtime_error(
            "smsgoutbox [all|clear]\n" 
            "Decrypt and display all sent messages.\n"
            "Warning: clear will delete all sent messages.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string mode = "all";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    }
    
    
    Object result;
    
    std::vector<unsigned char> vchUnread;
    std::vector<unsigned char> vchKey;
    vchKey.resize(16);
    memset(&vchKey[0], 0, 16);
    
    {
        LOCK(cs_smsgOutbox);
        
        CSmesgOutboxDB dbOutbox("cr+");
        
        char cbuf[256];
        
        if (mode == "clear")
        {
            //result.push_back(Pair("result", "Clear not implemented yet."));
            
            Dbc* pcursor = dbOutbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get outbox DB cursor");
            
            uint32_t nMessages = 0;
            
            std::set<std::vector<unsigned char> > setToDelete;
            std::set<std::vector<unsigned char> >::iterator itd;
            
            Dbt datKey;
            Dbt datValue;
            
            datKey.set_flags(DB_DBT_USERMEM);
            datValue.set_flags(DB_DBT_USERMEM);
            
            std::vector<unsigned char> vchDelete;
            std::vector<unsigned char> vchKeyData;
            std::vector<unsigned char> vchValueData;
            
            vchKeyData.resize(100);
            vchValueData.resize(100);
            
            datKey.set_ulen(vchKeyData.size());
            datKey.set_data(&vchKeyData[0]);
            
            datValue.set_ulen(vchValueData.size());
            datValue.set_data(&vchValueData[0]);
            
            unsigned int fFlags = DB_NEXT; // same as using DB_FIRST for new cursor
            while (true)
            {
                int ret = pcursor->get(&datKey, &datValue, fFlags);
                
                if (ret == ENOMEM
                    || ret == DB_BUFFER_SMALL)
                {
                    if (datKey.get_size() > datKey.get_ulen())
                    {
                        //printf("Resizing vchKeyData %d\n", datKey.get_size());
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
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s\n", ret, db_strerror(ret));
                    throw runtime_error(cbuf);
                };
                
                if (datKey.get_size() != 17)
                    continue; // not a message key
                
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datKey.get_data(), datKey.get_size());
                //SecOutboxMsg smsgOutbox;
                ssValue >> vchKey;
                
                setToDelete.insert(vchKey);
                
                /*
                // TODO: how to be sure data is really gone?
                if ((ret = pcursor->del(0)) != 0) // NOT working
                {
                    printf("Delete failed %d, %s\n", ret, db_strerror(ret));
                };
                */
                nMessages++;
            };
            pcursor->close();
            
            for (itd = setToDelete.begin(); itd != setToDelete.end(); ++itd)
            {
                std::vector<unsigned char> vchDeleteT = (*itd);
                dbOutbox.EraseSmesg(vchDeleteT);
            };
            
            
            snprintf(cbuf, sizeof(cbuf), "Deleted %u messages.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
            
        } else
        if (mode == "all")
        {
            Dbc* pcursor = dbOutbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get outbox DB cursor");
            
            
            uint32_t nMessages = 0;
            
            Dbt datKey;
            Dbt datValue;
            
            datKey.set_flags(DB_DBT_USERMEM);
            datValue.set_flags(DB_DBT_USERMEM);
            
            std::vector<unsigned char> vchKeyData;
            std::vector<unsigned char> vchValueData;
            
            vchKeyData.resize(100);
            vchValueData.resize(100);
            
            datKey.set_ulen(vchKeyData.size());
            datKey.set_data(&vchKeyData[0]);
            
            datValue.set_ulen(vchValueData.size());
            datValue.set_data(&vchValueData[0]);
            
            unsigned int fFlags = DB_NEXT; // same as using DB_FIRST for new cursor
            while (true)
            {
                int ret = pcursor->get(&datKey, &datValue, fFlags);
                
                if (ret == ENOMEM
                    || ret == DB_BUFFER_SMALL)
                {
                    if (datKey.get_size() > datKey.get_ulen())
                    {
                        printf("Resizing vchKeyData %d\n", datKey.get_size());
                        vchKeyData.resize(datKey.get_size());
                        datKey.set_ulen(vchKeyData.size());
                        datKey.set_data(&vchKeyData[0]);
                    };
                    
                    if (datValue.get_size() > datValue.get_ulen())
                    {
                        printf("Resizing vchValueData %d\n", datValue.get_size());
                        vchValueData.resize(datValue.get_size());
                        datValue.set_ulen(vchValueData.size());
                        datValue.set_data(&vchValueData[0]);
                    };
                    // try once more, when DB_BUFFER_SMALL cursor is not expected to move
                    ret = pcursor->get(&datKey, &datValue, fFlags);
                };
                
                if (ret == DB_NOTFOUND)
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s\n", ret, db_strerror(ret));
                    throw runtime_error(cbuf);
                };
                
                if (datKey.get_size() != 17)
                    continue; // not a message key
                
                nMessages++;
                // must be a better way?
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datValue.get_data(), datValue.get_size());
                
                SecOutboxMsg smsgOutbox;
                ssValue >> smsgOutbox;
                
                MessageData msg;
                
                uint32_t nPayload = smsgOutbox.vchMessage.size() - SMSG_HDR_LEN;
                
                if (SecureMsgDecrypt(false, smsgOutbox.sAddrOutbox, &smsgOutbox.vchMessage[0], &smsgOutbox.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {
                    Object objM;
                    objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("from", msg.sFromAddress));
                    objM.push_back(Pair("to", smsgOutbox.sAddrTo));
                    objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0]))); // ugh
                    
                    result.push_back(Pair("message", objM));
                } else
                {
                    result.push_back(Pair("message", "Could not decrypt."));
                };
            };

            pcursor->close();
            
            snprintf(cbuf, sizeof(cbuf), "%u sent messages shown.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
        } else
        {
            result.push_back(Pair("result", "Unknown Mode."));
            result.push_back(Pair("expected", "[all|clear]."));
        };
    }
    
    return result;
};


Value smsgbuckets(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "smsgbuckets [stats|dump]\n"
            "Display some statistics.");
    
    if (fNoSmsg)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string mode = "stats";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    };
    
    Object result;
    
    char cbuf[256];
    if (mode == "stats")
    {
        uint32_t nBuckets = 0;
        uint32_t nMessages = 0;
        uint64_t nBytes = 0;
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgSets.begin();
            
            for (it = smsgSets.begin(); it != smsgSets.end(); ++it)
            {
                std::set<SecMsgToken>& tokenSet = it->second.setTokens;
                
                std::string sBucket = boost::lexical_cast<std::string>(it->first);
                std::string sFile = sBucket + "_01.dat";
                
                snprintf(cbuf, sizeof(cbuf), "%lu", tokenSet.size());
                std::string snContents(cbuf);
                
                std::string sHash = boost::lexical_cast<std::string>(it->second.hash);
                
                nBuckets++;
                nMessages += tokenSet.size();
                
                Object objM;
                objM.push_back(Pair("bucket", sBucket));
                objM.push_back(Pair("time", getTimeString(it->first, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("no. messages", snContents));
                objM.push_back(Pair("hash", sHash));
                objM.push_back(Pair("last changed", getTimeString(it->second.timeChanged, cbuf, sizeof(cbuf))));
                
                try {
                    boost::filesystem::path fullPath = GetDataDir() / "smsgStore" / sFile;
                    uint64_t nFBytes = 0;
                    nFBytes = boost::filesystem::file_size(fullPath);
                    nBytes += nFBytes;
                    objM.push_back(Pair("file size", fsReadable(nFBytes)));
                } catch (const boost::filesystem::filesystem_error& ex)
                {
                    objM.push_back(Pair("file size, error", ex.what()));
                };
                
                result.push_back(Pair("bucket", objM));
            };
        }; // LOCK(cs_smsg);
        
        
        std::string snBuckets = boost::lexical_cast<std::string>(nBuckets);
        std::string snMessages = boost::lexical_cast<std::string>(nMessages);
        
        Object objM;
        objM.push_back(Pair("buckets", snBuckets));
        objM.push_back(Pair("messages", snMessages));
        objM.push_back(Pair("size", fsReadable(nBytes)));
        result.push_back(Pair("total", objM));
        
    } else
    if (mode == "dump")
    {
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgSets.begin();
            
            for (it = smsgSets.begin(); it != smsgSets.end(); ++it)
            {
                std::string sFile = boost::lexical_cast<std::string>(it->first) + "_01.dat";
                
                try {
                    boost::filesystem::path fullPath = GetDataDir() / "smsgStore" / sFile;
                    boost::filesystem::remove(fullPath);
                } catch (const boost::filesystem::filesystem_error& ex)
                {
                    //objM.push_back(Pair("file size, error", ex.what()));
                    printf("Error removing bucket file %s.\n", ex.what());
                };
            };
            smsgSets.clear();
        }; // LOCK(cs_smsg);
        
        result.push_back(Pair("result", "Removed all buckets."));
        
    } else
    {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "[stats|dump]."));
    }
    

    return result;
};
