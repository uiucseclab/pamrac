#include <vector>
using ::std::vector;
#include <string>
using ::std::string;
#include <array>
using ::std::array;
#include <fstream>

#include "sha256.h"
#include "base64.h"

#include "globals.h"

#include "utility.h"
#include "crypto.h"
#include "client_handler_session.h"

namespace pamrac {

array<char, SHA_LENGTH_BYTES> computeShareRequestDigest(ShareRequest const& the_request,
											array<char, SHA_LENGTH_BYTES> const& our_nonce)
{
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, the_request.share_id().originator_fingerprint().c_str(),
					   the_request.share_id().originator_fingerprint().length());
	SHA256_Update(&sha256, the_request.share_id().owner_fingerprint().c_str(),
					   the_request.share_id().owner_fingerprint().length());
	SHA256_Update(&sha256, the_request.share_id().encrypted_to_fingerprint().c_str(),
					   the_request.share_id().encrypted_to_fingerprint().length());
	SHA256_Update(&sha256, our_nonce.data(), our_nonce.size());
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);
	return computed_digest;
}

bool ClientHandlerSession::
verifyShareRequestSig(ShareRequest const& msg)
{
	array<char, SHA_LENGTH_BYTES> our_nonce;
	if(!nonce.pop(&our_nonce))
		return logErrorRetFalse(
			"verifyShareRequestSig() called when session did not have a nonce saved!");
	
	if(our_nonce.size() != msg.nonce().length() || memcmp(msg.nonce().c_str(), our_nonce.data(),
																our_nonce.size()))
	{
		return logErrorRetFalse(
			"verifyShareRequestSig(): their nonce does not match the nonce we saved!");
	}
	
		
	//verify that the outer Message's client_pubkey matches the inner encrypted_to_fp
	
	vector<char> key_fprint = fingerprintFromDERPubkey(client_supplied_pubkey);
	if(key_fprint.size() != msg.share_id().encrypted_to_fingerprint().length())
		return logErrorRetFalse(
			"verifyShareRequestSig(): key_fprint.size() != msg.share_id().encrypted_to_fingerprint().length()");
	
	for(int i=0; i<key_fprint.size(); i++)
		if(key_fprint[i] != msg.share_id().encrypted_to_fingerprint()[i])
			return logErrorRetFalse("verifyShareRequestSig(): key_fprint != encrypted_to_fingerprint");
	
	
	//verify that encrypted_to_fingerprint generated a valid sig(originator_fp~owner_fp~encrypted_to_fp~nonce)
	array<char, SHA_LENGTH_BYTES> our_digest = computeShareRequestDigest(msg, our_nonce);
	bool sig_is_good = (client_supplied_pubkey.size() > 9 &&
					verifyRSASig((uint8_t*)client_supplied_pubkey.data(), client_supplied_pubkey.size(),
							  (uint8_t*)msg.signature().c_str(), msg.signature().length(),
							  (uint8_t*)our_digest.data(), our_digest.size()));
	
	if(sig_is_good)
		return true;
	return logErrorRetFalse("A verifyShareRequestSig() failed!");
}

bool parseKeyShareFile(KeyShare* key_share, string orig_fp_bytes,
									string owner_fp_bytes,
									string enc_to_fp_bytes)
{
	string orig_fp_base64 = base64_encode((uint8_t*)orig_fp_bytes.c_str(), orig_fp_bytes.length());
	string owner_fp_base64 = base64_encode((uint8_t*)owner_fp_bytes.c_str(), owner_fp_bytes.length());
	string enc_to_fp_base64 = base64_encode((uint8_t*)enc_to_fp_bytes.c_str(), enc_to_fp_bytes.length());
	
	string full_filename = g_stores_base_dirpath + "/keyshares/" + orig_fp_base64 + "-" + 
											owner_fp_base64 + "-" +
											enc_to_fp_base64;
	
	std::ifstream reader(full_filename, std::ifstream::binary);
	if(!reader)
		return logErrorRetFalse("Could not read "+full_filename);
	bool parse_ok = key_share->ParseFromIstream(&reader);
	return parse_ok;
}

bool ClientHandlerSession::
handleShareRequest(pamrac::ShareRequest const& msg)
{
	if(!verifyShareRequestSig(msg))
		return logErrorRetFalse("ShareRequest had a bad signature. Giving up on this session.");
	
	PAMRACMessage response;
	KeyShare share_response;
	if(!parseKeyShareFile(&share_response, msg.share_id().originator_fingerprint(),
									msg.share_id().owner_fingerprint(),
									 msg.share_id().encrypted_to_fingerprint()))
	{
		response.set_type(PAMRACMessage_Type_NOT_AUTHORIZED);
	}
	else
	{
		response.set_type(PAMRACMessage_Type_KEY_SHARE);
		*(response.mutable_key_share()) = share_response;
		//NOTE: the share file will either have masterkey_retrievable_file and encrypted_initiator_mask,
		//		and the parsing will populate those fields, or else they are not meant to be in there.
	}
	
	sendPAMRACMessage(response);
	return false;
}

} //end pamrac namespace
