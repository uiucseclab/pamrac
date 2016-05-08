#include <vector>
using ::std::vector;
#include <array>
using ::std::array;
#include <string>
using ::std::string;

#include <mbedtls/pk.h>

#include "sha256.h"
#include "base64.h"

#include "constants.h"

#include "crypto.h"

//Returns true if the signature is a valid signature of the digest made 
//by the specified public key. (digest should just be a hash, e.g. for SHA256, digest_len should be 32).
bool verifyRSASig(const uint8_t* der_format_pubkey, int pubkey_len,
				const uint8_t* signature, int signature_len,
				const uint8_t* digest, int digest_len)
{
	int ret;
	
	mbedtls_pk_context pubkey_ctx;
	mbedtls_pk_init(&pubkey_ctx);
	if(0 != (ret = mbedtls_pk_parse_key(&pubkey_ctx, der_format_pubkey, pubkey_len, 0, 0)))
	{
		//TODO handle error; error code ret
		mbedtls_pk_free(&pubkey_ctx);
		return false;
	}
	
	ret = mbedtls_pk_verify(&pubkey_ctx, MBEDTLS_MD_NONE, digest, digest_len, signature, signature_len);
	if(ret != 0 && ret != MBEDTLS_ERR_PK_SIG_LEN_MISMATCH)
	{
		//TODO handle error / verification fail
		mbedtls_pk_free(&pubkey_ctx);
		return false;
	}
	mbedtls_pk_free(&pubkey_ctx);
	return true;
	
	
	/*rsa_context rsa;
	rsa_init(&rsa, RSA_PKCS_V15, 0);
	//TODO LOAD der_format_pubkey INTO HERE
	
	//could specify RSA_SHA256 instead of RSA_RAW, but... cleaner to use the .size() of the array.
	bool sig_is_good = (0 == rsa_pkcs1_verify(&rsa, RSA_PUBLIC, RSA_RAW, our_digest.size(),
									  our_digest.data(), signature));
	
	rsa_free(&rsa);
	return sig_is_good;*/
}

array<char, PAMRAC_FINGERPRINT_SIZE> fingerprintFromDERPubkey(vector<char> const& pubkey)
{
	if(pubkey.size() == 0)
		return {0};
	
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, pubkey.data(),
					    pubkey.size());
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);

	array<char, PAMRAC_FINGERPRINT_SIZE> chopped;
	for(int i=0; i<PAMRAC_FINGERPRINT_SIZE; i++)
		chopped[i] = computed_digest[i];
	
	return chopped;
}

array<char, PAMRAC_FINGERPRINT_SIZE> fingerprintFromDERPubkey(string const& pubkey)
{
	if(pubkey.length() == 0)
		return {0};
	
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, pubkey.c_str(),
					    pubkey.length());
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);

	array<char, PAMRAC_FINGERPRINT_SIZE> chopped;
	for(int i=0; i<PAMRAC_FINGERPRINT_SIZE; i++)
		chopped[i] = computed_digest[i];
	
	return chopped;
}

string base64FingerprintFromDERPubkey(vector<char> const& pubkey)
{
	if(pubkey.size() == 0)
		return "bad";
	
	array<char, PAMRAC_FINGERPRINT_SIZE> fp_bytes = fingerprintFromDERPubkey(pubkey);
	return base64_encode((uint8_t*)fp_bytes.data(), fp_bytes.size());
}

string base64FingerprintFromDERPubkey(string const& pubkey)
{
	if(pubkey.size() == 0)
		return "bad";
	
	array<char, PAMRAC_FINGERPRINT_SIZE> fp_bytes = fingerprintFromDERPubkey(pubkey);
	return base64_encode((uint8_t*)fp_bytes.data(), fp_bytes.size());
}



/*bool parseRSAKey(const uint8_t* ???
{
}
*/
