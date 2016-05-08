#include <vector>
using ::std::vector;
#include <string>
using ::std::string;
#include <array>
using ::std::array;
#include <fstream>

#include "sha256.h"

#include "constants.h"
#include "utility.h"
#include "crypto.h"

#include "client_handler_session.h"

namespace pamrac {

	
array<char, SHA_LENGTH_BYTES> computeShareListRequestDigest(ShareListRequest const& the_request,
											array<char, SHA_LENGTH_BYTES> const& our_nonce)
{
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, the_request.requester_fingerprint().c_str(),
					    the_request.requester_fingerprint().length());
	SHA256_Update(&sha256, our_nonce.data(), our_nonce.size());
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);
	return computed_digest;
}

bool ClientHandlerSession::
verifyShareListRequestSig(ShareListRequest const& msg)
{
	array<char, SHA_LENGTH_BYTES> our_nonce;
	if(!nonce.pop(&our_nonce))
		return logErrorRetFalse(
			"verifyShareListRequestSig() called when session did not have a nonce saved!");
		
	if(our_nonce.size() != msg.nonce().length() || memcmp(msg.nonce().c_str(), our_nonce.data(),
																our_nonce.size()))
	{
		return logErrorRetFalse(
			"verifyShareListRequestSig(): their nonce does not match the nonce we saved!");
	}
		
	//verify that the outer Message's client_pubkey matches the inner requester_fingerprint
	
	array<char, PAMRAC_FINGERPRINT_SIZE> key_fprint = fingerprintFromDERPubkey(client_supplied_pubkey);
	if(msg.requester_fingerprint().length() != PAMRAC_FINGERPRINT_SIZE)
		return logErrorRetFalse(
			"verifyShareListRequestSig(): msg.requester_fingerprint().length() != PAMRAC_FINGERPRINT_SIZE");
	
	for(int i=0; i<key_fprint.size(); i++)
		if(key_fprint[i] != msg.requester_fingerprint()[i])
			return logErrorRetFalse("verifyShareListRequestSig(): key_fprint != requested_fingerprint");
	
	
	//verify that client_pubkey generated the signature of req_fp~nonce, and that the sig matches	
	array<char, SHA_LENGTH_BYTES> our_digest = computeShareListRequestDigest(msg, our_nonce);
	bool sig_is_good = (client_supplied_pubkey.size() > 9 &&
					verifyRSASig((uint8_t*)client_supplied_pubkey.data(), client_supplied_pubkey.size(),
							  (uint8_t*)msg.signature().c_str(), msg.signature().length(),
							  (uint8_t*)our_digest.data(), our_digest.size()));
	
	if(sig_is_good)
		return true;
	return logErrorRetFalse("A verifyShareListRequestSig() failed!");
}

bool ClientHandlerSession::
parseShareListFile(ShareList* response_content)
{
	string base_dir;
	if(!cur_client_store.getUserStoreDir(&base_dir))
		return logErrorRetFalse("Could not get user's base directory path to retrieve a ShareList.");
	string filename = base_dir+"/"+SHARE_LIST_FILE_NAME;
	
	std::ifstream reader(filename, std::ifstream::binary);
	if(!reader)
		return logErrorRetFalse("Could not read from "+filename);
	bool parse_ok = response_content->ParseFromIstream(&reader);
	return parse_ok;
}

bool fingerprintListedAsInitiator(ShareList const& list, string const& fingerprint_bytes)
{
	for(int i=0; i<list.recipients_size(); i++)
		if(list.recipients(i).initiator() && list.recipients(i).fingerprint() == fingerprint_bytes)
			return true;
	return false;
}
	
bool ClientHandlerSession::
handleShareListRequest(ShareListRequest const& msg)
{
	if(!verifyShareListRequestSig(msg))
		return logErrorRetFalse("ShareListRequest had a bad signature. Giving up on this session.");
	
	ShareList response_content;
	if(!parseShareListFile(&response_content))
		return logErrorRetFalse("Failed to parse ShareList.");
	
	PAMRACMessage response;
	if(!fingerprintListedAsInitiator(response_content, msg.requester_fingerprint()))
		response.set_type(PAMRACMessage_Type_NOT_AUTHORIZED); //Tell them they're not authorized - that's it.
	else
	{
		response.set_type(PAMRACMessage_Type_SHARE_LIST);
		*(response.mutable_share_list()) = response_content;
	}
	sendPAMRACMessage(response);
	return false;
}

} //end pamrac namespace
