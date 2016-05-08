#ifndef _INCLGUARD_PAMRAC_UTILITY_H_ 
#define _INCLGUARD_PAMRAC_UTILITY_H_

#include <vector>
#include <string>
#include <array>

#include "constants.h"

void logError(std::string the_message);
bool logErrorRetFalse(std::string the_message);
void exitError(std::string the_message);
bool readRandomBytes(char* output, int bytes_to_read);
bool listDirectorysFiles(std::vector<std::string>* output, std::string dirpath);
bool fileContentsSHA256(std::array<char, SHA_LENGTH_BYTES>* output, std::string filepath);

#endif //_INCLGUARD_PAMRAC_UTILITY_H_
