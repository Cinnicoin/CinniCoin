// Copyright (c) 2014 The CinniCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/*
    Link in bitcoinrpc.h/cpp
*/

#include "main.h"
#include "bitcoinrpc.h"

#include "emessage.h"

using namespace json_spirit;
using namespace std;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

Value smsgscanchain(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanchain \n"
            "Look for public keys in the block chain.");

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

    std::string addr = params[0].get_str();
    std::string pubk = params[1].get_str();
    
    Object result;
    
    if (SecureMsgAddAddress(addr, pubk) != 0)
        result.push_back(Pair("result", "Public key not added to db."));
    else
        result.push_back(Pair("result", "Added public key to db."));
    
    return result;
}

Value smsgsend(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "smsgsend <addrFrom> <addrTo> <message>\n"
            "Send an encrypted message from addrFrom to addrTo.");

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

Value smsggetlocalpubkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "smsggetlocalpubkey <address>\n"
            "Return the uncompressed public key for an address in your wallet.");

    std::string address   = params[0].get_str();
    std::string publicKey;
    
    
    int rv = GetLocalPublicKey(address, publicKey);
    
    Object result;
    
    switch (rv)
    {
        case 0:
            result.push_back(Pair("result", "Success."));
            result.push_back(Pair("address", address));
            result.push_back(Pair("full public key", publicKey));
            break;
        case 1:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Error."));
            break;
        case 2:
        case 3:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Invalid address."));
            break;
        case 4:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Address not found in wallet."));
            break;
    };

    return result;
}
