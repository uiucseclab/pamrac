#ifndef _INCLGUARD_PAMRAC_GLOBALS_H_
#define _INCLGUARD_PAMRAC_GLOBALS_H_

#include <string>
#include <array>
#include <vector>
#include <unordered_map>

#include "client_store.h"
#include "constants.h"

extern std::string g_logError_target_filename;
extern std::unordered_map<std::string, std::string> g_joining_passcodes;

extern std::string g_stores_base_dirpath;

//Map key is base64(fingerprint of that client's public key)
extern std::unordered_map<std::string, pamrac::ClientStore> g_all_hosted_clients;


#endif //_INCLGUARD_PAMRAC_GLOBALS_H_
