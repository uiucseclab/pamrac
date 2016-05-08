#ifndef _INCLGUARD_PAMRAC_CRYPTO_H_ 
#define _INCLGUARD_PAMRAC_CRYPTO_H_

//HACK SHOULD NOT BE NECESSARY WTF
#include <cstdint>

#include <vector>
#include <string>

#include "constants.h"

//Returns true if the signature is a valid signature of the digest made 
//by the specified public key. (digest should just be a hash, e.g. for SHA256, digest_len should be 32).
bool verifyRSASig(const uint8_t* der_format_pubkey, int pubkey_len,
				const uint8_t* signature, int signature_len,
				const uint8_t* digest, int digest_len);

std::array<char, PAMRAC_FINGERPRINT_SIZE> fingerprintFromDERPubkey(std::vector<char> const& pubkey);
std::array<char, PAMRAC_FINGERPRINT_SIZE> fingerprintFromDERPubkey(std::string const& pubkey);
std::string base64FingerprintFromDERPubkey(std::vector<char> const& pubkey);
std::string base64FingerprintFromDERPubkey(std::string const& pubkey);


#endif //_INCLGUARD_PAMRAC_CRYPTO_H_
