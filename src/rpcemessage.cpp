// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"

#include <boost/lexical_cast.hpp>

#include "emessage.h"
#include "init.h" // pwalletMain

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);



Value smsgenable(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgenable \n"
            "Enable secure messaging.");
    
    if (fSecMsgEnabled)
        throw runtime_error("Secure messaging is already enabled.");
    
    Object result;
    if (!SecureMsgEnable())
    {
        result.push_back(Pair("result", "Failed to enable secure messaging."));
    } else
    {
        result.push_back(Pair("result", "Enabled secure messaging."));
    }
    return result;
}

Value smsgdisable(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgdisable \n"
            "Disable secure messaging.");
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is already disabled.");
    
    Object result;
    if (!SecureMsgDisable())
    {
        result.push_back(Pair("result", "Failed to disable secure messaging."));
    } else
    {
        result.push_back(Pair("result", "Disabled secure messaging."));
    }
    return result;
}

Value smsgoptions(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "smsgoptions [list|set <optname> <value>]\n"
            "List and manage options.");
    
    std::string mode = "list";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    };
    
    Object result;
    //char cbuf[256];
    
    if (mode == "list")
    {
        result.push_back(Pair("option", std::string("newAddressRecv = ") + (smsgOptions.fNewAddressRecv ? "true" : "false")));
        result.push_back(Pair("option", std::string("newAddressAnon = ") + (smsgOptions.fNewAddressAnon ? "true" : "false")));
        
        result.push_back(Pair("result", "Success."));
    } else
    if (mode == "set")
    {
        if (params.size() < 3)
        {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "set <optname> <value>"));
            return result;
        };
        
        std::string optname = params[1].get_str();
        std::string value   = params[2].get_str();
        
        if (optname == "newAddressRecv")
        {
            if (value == "+" || value == "on"  || value == "true"  || value == "1")
            {
                smsgOptions.fNewAddressRecv = true;
            } else
            if (value == "-" || value == "off" || value == "false" || value == "0")
            {
                smsgOptions.fNewAddressRecv = false;
            } else
            {
                result.push_back(Pair("result", "Unknown value."));
                return result;
            };
            result.push_back(Pair("set option", std::string("newAddressRecv = ") + (smsgOptions.fNewAddressRecv ? "true" : "false")));
        } else
        if (optname == "newAddressAnon")
        {
            if (value == "+" || value == "on"  || value == "true"  || value == "1")
            {
                smsgOptions.fNewAddressAnon = true;
            } else
            if (value == "-" || value == "off" || value == "false" || value == "0")
            {
                smsgOptions.fNewAddressAnon = false;
            } else
            {
                result.push_back(Pair("result", "Unknown value."));
                return result;
            };
            result.push_back(Pair("set option", std::string("newAddressAnon = ") + (smsgOptions.fNewAddressAnon ? "true" : "false")));
        } else
        {
            result.push_back(Pair("result", "Option not found."));
            return result;
        };
        
        
    } else
    {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "smsgoption [list|set <optname> <value>]"));
    };
    return result;
}

Value smsglocalkeys(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "smsglocalkeys [whitelist|all|wallet|recv <+/-> <address>|anon <+/-> <address>]\n"
            "List and manage keys.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    Object result;
    
    std::string mode = "whitelist";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    };
    
    char cbuf[256];
    
    if (mode == "whitelist"
        || mode == "all")
    {
        uint32_t nKeys = 0;
        int all = mode == "all" ? 1 : 0;
        for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (!all 
                && !it->fReceiveEnabled)
                continue;
            
            CBitcoinAddress coinAddress(it->sAddress);
            if (!coinAddress.IsValid())
                continue;
            
            std::string sPublicKey;
            
            CKeyID keyID;
            if (!coinAddress.GetKeyID(keyID))
                continue;
            
            CPubKey pubKey;
            if (!pwalletMain->GetPubKey(keyID, pubKey))
                continue;
            if (!pubKey.IsValid()
                || !pubKey.IsCompressed())
            {
                continue;
            };
            
            
            sPublicKey = EncodeBase58(pubKey.Raw());
            
            std::string sLabel = pwalletMain->mapAddressBook[keyID];
            std::string sInfo;
            if (all)
                sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on,  " : "off, ");
            sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
            result.push_back(Pair("key", it->sAddress + " - " + sPublicKey + " " + sInfo + " - " + sLabel));
            
            nKeys++;
        };
        
        
        snprintf(cbuf, sizeof(cbuf), "%u keys listed.", nKeys);
        result.push_back(Pair("result", std::string(cbuf)));
        
    } else
    if (mode == "recv")
    {
        if (params.size() < 3)
        {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "recv <+/-> <address>"));
            return result;
        };
        
        std::string op      = params[1].get_str();
        std::string addr    = params[2].get_str();
        
        std::vector<SecMsgAddress>::iterator it;
        for (it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (addr != it->sAddress)
                continue;
            break;
        };
        
        if (it == smsgAddresses.end())
        {
            result.push_back(Pair("result", "Address not found."));
            return result;
        };
        
        if (op == "+" || op == "on"  || op == "add" || op == "a")
        {
            it->fReceiveEnabled = true;
        } else
        if (op == "-" || op == "off" || op == "rem" || op == "r")
        {
            it->fReceiveEnabled = false;
        } else
        {
            result.push_back(Pair("result", "Unknown operation."));
            return result;
        };
        
        std::string sInfo;
        sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on, " : "off,");
        sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
        result.push_back(Pair("result", "Success."));
        result.push_back(Pair("key", it->sAddress + " " + sInfo));
        return result;
        
    } else
    if (mode == "anon")
    {
        if (params.size() < 3)
        {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "anon <+/-> <address>"));
            return result;
        };
        
        std::string op      = params[1].get_str();
        std::string addr    = params[2].get_str();
        
        std::vector<SecMsgAddress>::iterator it;
        for (it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (addr != it->sAddress)
                continue;
            break;
        };
        
        if (it == smsgAddresses.end())
        {
            result.push_back(Pair("result", "Address not found."));
            return result;
        };
        
        if (op == "+" || op == "on"  || op == "add" || op == "a")
        {
            it->fReceiveAnon = true;
        } else
        if (op == "-" || op == "off" || op == "rem" || op == "r")
        {
            it->fReceiveAnon = false;
        } else
        {
            result.push_back(Pair("result", "Unknown operation."));
            return result;
        };
        
        std::string sInfo;
        sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on, " : "off,");
        sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
        result.push_back(Pair("result", "Success."));
        result.push_back(Pair("key", it->sAddress + " " + sInfo));
        return result;
        
    } else
    if (mode == "wallet")
    {
        uint32_t nKeys = 0;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, std::string)& entry, pwalletMain->mapAddressBook)
        {
            if (!IsMine(*pwalletMain, entry.first))
                continue;
            
            CBitcoinAddress coinAddress(entry.first);
            if (!coinAddress.IsValid())
                continue;
            
            std::string address;
            std::string sPublicKey;
            address = coinAddress.ToString();
            
            CKeyID keyID;
            if (!coinAddress.GetKeyID(keyID))
                continue;
            
            CPubKey pubKey;
            if (!pwalletMain->GetPubKey(keyID, pubKey))
                continue;
            if (!pubKey.IsValid()
                || !pubKey.IsCompressed())
            {
                continue;
            };
            
            sPublicKey = EncodeBase58(pubKey.Raw());
            
            result.push_back(Pair("key", address + " - " + sPublicKey + " - " + entry.second));
            nKeys++;
        };
        
        snprintf(cbuf, sizeof(cbuf), "%u keys listed from wallet.", nKeys);
        result.push_back(Pair("result", std::string(cbuf)));
    } else
    {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "smsglocalkeys [whitelist|all|wallet|recv <+/-> <address>|anon <+/-> <address>]"));
    };
    
    return result;
};

Value smsgscanchain(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanchain \n"
            "Look for public keys in the block chain.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    Object result;
    if (!SecureMsgScanBlockChain())
    {
        result.push_back(Pair("result", "Scan Chain Failed."));
    } else
    {
        result.push_back(Pair("result", "Scan Chain Completed."));
    }
    return result;
}

Value smsgscanbuckets(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanbuckets \n"
            "Force rescan of all messages in the bucket store.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");
    
    Object result;
    if (!SecureMsgScanBuckets())
    {
        result.push_back(Pair("result", "Scan Buckets Failed."));
    } else
    {
        result.push_back(Pair("result", "Scan Buckets Completed."));
    }
    return result;
}

Value smsgaddkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgaddkey <address> <pubkey>\n"
            "Add address, pubkey pair to database.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addr = params[0].get_str();
    std::string pubk = params[1].get_str();
    
    Object result;
    int rv = SecureMsgAddAddress(addr, pubk);
    if (rv != 0)
    {
        result.push_back(Pair("result", "Public key not added to db."));
        switch (rv)
        {
            case 2:     result.push_back(Pair("reason", "publicKey is invalid."));                  break;
            case 3:     result.push_back(Pair("reason", "publicKey does not match address."));      break;
            case 4:     result.push_back(Pair("reason", "address is already in db."));              break;
            case 5:     result.push_back(Pair("reason", "address is invalid."));                    break;
            default:    result.push_back(Pair("reason", "error."));                                 break;
        };
    } else
    {
        result.push_back(Pair("result", "Added public key to db."));
    };
    
    return result;
}

Value smsggetpubkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "smsggetpubkey <address>\n"
            "Return the base58 encoded compressed public key for an address.\n"
            "Tests localkeys first, then looks in public key db.\n");
    
    if (!fSecMsgEnabled)
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

Value smsgsend(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "smsgsend <addrFrom> <addrTo> <message>\n"
            "Send an encrypted message from addrFrom to addrTo.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addrFrom  = params[0].get_str();
    std::string addrTo    = params[1].get_str();
    std::string msg       = params[2].get_str();
    
    
    Object result;
    
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    } else
        result.push_back(Pair("result", "Sent."));

    return result;
}

Value smsgsendanon(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgsendanon <addrTo> <message>\n"
            "Send an anonymous encrypted message to addrTo.");
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    std::string addrFrom  = "anon";
    std::string addrTo    = params[0].get_str();
    std::string msg       = params[1].get_str();
    
    
    Object result;
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0)
    {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    } else
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
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");
    
    std::string mode = "unread";
    if (params.size() > 0)
    {
        mode = params[0].get_str();
    }
    
    
    Object result;
    
    std::vector<unsigned char> vchKey;
    vchKey.resize(16);
    memset(&vchKey[0], 0, 16);
    
    {
        LOCK(cs_smsgInbox);
        
        CSmesgInboxDB dbInbox("cr+");
        
        char cbuf[256];
        
        if (mode == "clear")
        {
            dbInbox.TxnBegin();
            Dbc* pcursor = dbInbox.GetTxnCursor();
            //Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get inbox DB cursor");
            
            uint32_t nMessages = 0;
            
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
                        vchKeyData.resize(datKey.get_size());
                        datKey.set_ulen(vchKeyData.size());
                        datKey.set_data(&vchKeyData[0]);
                    };
                    
                    if (datValue.get_size() > datValue.get_ulen())
                    {
                        vchValueData.resize(datValue.get_size());
                        datValue.set_ulen(vchValueData.size());
                        datValue.set_data(&vchValueData[0]);
                    };
                    // -- try once more, when DB_BUFFER_SMALL cursor is not expected to move
                    ret = pcursor->get(&datKey, &datValue, fFlags);
                };
                
                if (ret == DB_NOTFOUND)
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s", ret, db_strerror(ret));
                    throw runtime_error(cbuf);
                };
                
                if (datKey.get_size() != 17)
                    continue; // not a message key
                
                CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                ssValue.SetType(SER_DISK);
                ssValue.clear();
                ssValue.write((char*)datKey.get_data(), datKey.get_size());
                ssValue >> vchKey;
                
                if ((ret = pcursor->del(0)) != 0)
                {
                    printf("Delete failed %d, %s\n", ret, db_strerror(ret));
                };
                nMessages++;
            };
            pcursor->close();
            dbInbox.TxnCommit();
            
            
            
            snprintf(cbuf, sizeof(cbuf), "Deleted %u messages.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
            
        } else
        if (mode == "all"
            || mode == "unread")
        {
            int fCheckReadStatus = mode == "unread" ? 1 : 0;
            
            dbInbox.TxnBegin();
            Dbc* pcursor = dbInbox.GetTxnCursor();
            //Dbc* pcursor = dbInbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get inbox DB cursor");
            
            
            uint32_t nMessages = 0;
            
            SecInboxMsg smsgInbox;
            MessageData msg;
            
            unsigned int fFlags = DB_FIRST;
            
            while (dbInbox.NextSmesg(pcursor, fFlags, vchKey, smsgInbox))
            {
                fFlags = DB_NEXT;
                
                if (fCheckReadStatus
                    && !(smsgInbox.status & SMSG_MASK_UNREAD))
                    continue;
                
                
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
                
                nMessages++;
                
                if (fCheckReadStatus)
                {
                    smsgInbox.status &= ~SMSG_MASK_UNREAD;
                    
                    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
                    ssKey.reserve(vchKey.size());
                    ssKey << vchKey;
                    Dbt datKey(&ssKey[0], ssKey.size());
                    CDataStream ssValue(SER_DISK, CLIENT_VERSION);
                    ssValue.clear();
                    ssValue << smsgInbox;
                    Dbt datValue(&ssValue[0], ssValue.size());
                    
                    int ret;
                    if ((ret = pcursor->put(&datKey, &datValue, DB_CURRENT)) != 0)
                    {
                         snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s", ret, db_strerror(ret));
                        throw runtime_error(cbuf);
                    }
                };
            };
            
            
            pcursor->close();
            dbInbox.TxnCommit();
            
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
    
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");
    
    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");
    
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
            dbOutbox.TxnBegin();
            Dbc* pcursor = dbOutbox.GetTxnCursor();
            //Dbc* pcursor = dbOutbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get outbox DB cursor");
            
            uint32_t nMessages = 0;
            
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
                        vchKeyData.resize(datKey.get_size());
                        datKey.set_ulen(vchKeyData.size());
                        datKey.set_data(&vchKeyData[0]);
                    };
                    
                    if (datValue.get_size() > datValue.get_ulen())
                    {
                        vchValueData.resize(datValue.get_size());
                        datValue.set_ulen(vchValueData.size());
                        datValue.set_data(&vchValueData[0]);
                    };
                    // -- try once more, when DB_BUFFER_SMALL cursor is not expected to move
                    ret = pcursor->get(&datKey, &datValue, fFlags);
                };
                
                if (ret == DB_NOTFOUND)
                    break;
                else
                if (datKey.get_data() == NULL || datValue.get_data() == NULL
                    || ret != 0)
                {
                    snprintf(cbuf, sizeof(cbuf), "inbox DB error %d, %s", ret, db_strerror(ret));
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
                
                
                if ((ret = pcursor->del(0)) != 0)
                {
                    printf("Delete failed %d, %s\n", ret, db_strerror(ret));
                };
                
                nMessages++;
            };
            pcursor->close();
            dbOutbox.TxnCommit();
            
            
            snprintf(cbuf, sizeof(cbuf), "Deleted %u messages.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
            
        } else
        if (mode == "all")
        {
            Dbc* pcursor = dbOutbox.GetAtCursor();
            if (!pcursor)
                throw runtime_error("Cannot get outbox DB cursor");
            
            
            uint32_t nMessages = 0;
            
            SecOutboxMsg smsgOutbox;
            unsigned int fFlags = DB_FIRST;
            
            while (dbOutbox.NextSmesg(pcursor, fFlags, vchKey, smsgOutbox))
            {
                fFlags = DB_NEXT;
                
                nMessages++;
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
    
    if (!fSecMsgEnabled)
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
            it = smsgBuckets.begin();
            
            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
            {
                std::set<SecMsgToken>& tokenSet = it->second.setTokens;
                
                std::string sBucket = boost::lexical_cast<std::string>(it->first);
                std::string sFile = sBucket + "_01.dat";
                
                snprintf(cbuf, sizeof(cbuf), "%"PRIszu, tokenSet.size());
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
                
                boost::filesystem::path fullPath = GetDataDir() / "smsgStore" / sFile;


                if (!boost::filesystem::exists(fullPath))
                {
                    // -- If there is a file for an empty bucket something is wrong.
                    if (tokenSet.size() == 0)
                        objM.push_back(Pair("file size", "Empty bucket."));
                    else
                        objM.push_back(Pair("file size, error", "File not found."));
                } else
                {
                    try {
                        
                        uint64_t nFBytes = 0;
                        nFBytes = boost::filesystem::file_size(fullPath);
                        nBytes += nFBytes;
                        objM.push_back(Pair("file size", fsReadable(nFBytes)));
                    } catch (const boost::filesystem::filesystem_error& ex)
                    {
                        objM.push_back(Pair("file size, error", ex.what()));
                    };
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
            it = smsgBuckets.begin();
            
            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
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
            smsgBuckets.clear();
        }; // LOCK(cs_smsg);
        
        result.push_back(Pair("result", "Removed all buckets."));
        
    } else
    {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "[stats|dump]."));
    };
    

    return result;
};
