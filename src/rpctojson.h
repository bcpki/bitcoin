#ifndef RPCTOJSON_H
#define RPCTOJSON_H

#include "script.h"
#include "json/json_spirit_utils.h"

void rpc_ScriptPubKeyToJSON(const CScript& scriptPubKey, json_spirit::Object& out);
json_spirit::Value rpc_TxToJSON(const CTransaction& tx);
#endif 
