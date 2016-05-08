#include <string>
#include <array>
#include <vector>
#include <unordered_map>

#include "constants.h"
#include "globals.h"


std::string g_logError_target_filename;
std::unordered_map<std::string, std::string> g_joining_passcodes;

std::string g_stores_base_dirpath;

//Map key is base64(fingerprint of that client's public key)
std::unordered_map<std::string, pamrac::ClientStore> g_all_hosted_clients;
