#include <unistd.h>

#include <string>
using ::std::string;
#include <vector>
using ::std::vector;
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

	
//Compute the following SHA256 hash:
//	for each revoke_id:
//		SHA256Update(revoke_id.[originator~owner~encryptedTo])
//	for each share:
//		SHA256Update(toString(share.timestamp))
//		if(share has a masterkey_retrievable_file)
//			SHA256Update(share.mkey_ret_file.[toString(timestamp)~initvec~ciphertext])
//		if(share has a encrypted_initiator_mask)
//			SHA256Update(share.encrypted_initiator_mask)
//		SHA256Update(share.encrypted_share)
//		SHA256Update(share.share_id.[originator~owner~encryptedTo])
//	SHA256Update(nonce)
//	SHA256Finish()
array<char, SHA_LENGTH_BYTES> computeShareUploadDigest(ShareUpload const& the_upload,
											array<char, SHA_LENGTH_BYTES> const& our_nonce)
{
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	
	for(int i=0; i<the_upload.revoke_id_size(); i++)
	{
		SHA256_Update(&sha256, the_upload.revoke_id(i).originator_fingerprint().c_str(),
						    the_upload.revoke_id(i).originator_fingerprint().length());
		SHA256_Update(&sha256, the_upload.revoke_id(i).owner_fingerprint().c_str(),
						    the_upload.revoke_id(i).owner_fingerprint().length());
		SHA256_Update(&sha256, the_upload.revoke_id(i).encrypted_to_fingerprint().c_str(),
						    the_upload.revoke_id(i).encrypted_to_fingerprint().length());
	}
	for(int i=0; i<the_upload.share_size(); i++)
	{
		string share_timestamp_str = std::to_string(the_upload.share(i).timestamp());
		SHA256_Update(&sha256, share_timestamp_str.c_str(), share_timestamp_str.length());
		
		if(the_upload.share(i).has_masterkey_retrievable_file())
		{
			MasterKeyRetrievableFile const& mkrf = the_upload.share(i).masterkey_retrievable_file();
			
			string mkrf_timestamp_str = std::to_string(mkrf.timestamp());
			
			SHA256_Update(&sha256, mkrf_timestamp_str.c_str(), 
								mkrf_timestamp_str.length());
			SHA256_Update(&sha256, mkrf.aes_init_vector().c_str(), 
								mkrf.aes_init_vector().length());
			SHA256_Update(&sha256, mkrf.inner_retrievable_ciphertext().c_str(),
								mkrf.inner_retrievable_ciphertext().length());
		}
		if(the_upload.share(i).has_encrypted_initiator_mask())
		{
			SHA256_Update(&sha256, the_upload.share(i).encrypted_initiator_mask().c_str(),
								the_upload.share(i).encrypted_initiator_mask().length());
		}
		SHA256_Update(&sha256, the_upload.share(i).encrypted_share().c_str(),
							the_upload.share(i).encrypted_share().length());
		
		ShareID const& share_id = the_upload.share(i).share_id();
		SHA256_Update(&sha256, share_id.originator_fingerprint().c_str(),
						    share_id.originator_fingerprint().length());
		SHA256_Update(&sha256, share_id.owner_fingerprint().c_str(),
						    share_id.owner_fingerprint().length());
		SHA256_Update(&sha256, share_id.encrypted_to_fingerprint().c_str(),
						    share_id.encrypted_to_fingerprint().length());
	}
	SHA256_Update(&sha256, our_nonce.data(), our_nonce.size());
	
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);
	return computed_digest;
}

bool ClientHandlerSession::
verifyShareUploadSig(ShareUpload const& msg)
{
	array<char, SHA_LENGTH_BYTES> our_nonce;
	if(!nonce.pop(&our_nonce))
		return logErrorRetFalse("verifyShareUploadSig() called when session did not have a nonce saved!");
	if(our_nonce.size() != msg.nonce().length() || memcmp(msg.nonce().c_str(), our_nonce.data(),
																our_nonce.size()))
	{
		return logErrorRetFalse("verifyShareUploadSig(): their nonce does not match the nonce we saved!");
	}
	
	array<char, SHA_LENGTH_BYTES> our_digest = computeShareUploadDigest(msg, our_nonce);
	
	vector<char> store_owner_pubkey;
	if(!cur_client_store.getStoreOwnerPubkey(&store_owner_pubkey))
		return logErrorRetFalse("verifyShareUploadSig() called with unitialized store context (no pubkey).");
	
	//Upload might come from either the store owner, or from some other person. So, try to verify 
	//both with cur_client_store.getStoreOwnerPubkey() and with client_supplied_pubkey (if present).
	bool sig_is_good = (verifyRSASig((uint8_t*)store_owner_pubkey.data(), store_owner_pubkey.size(),
							  (uint8_t*)msg.signature().c_str(), msg.signature().length(),
							  (uint8_t*)our_digest.data(), our_digest.size())
						||
					(client_supplied_pubkey.size() > 9 &&
					verifyRSASig((uint8_t*)client_supplied_pubkey.data(), client_supplied_pubkey.size(),
							  (uint8_t*)msg.signature().c_str(), msg.signature().length(),
							  (uint8_t*)our_digest.data(), our_digest.size())));
	
	if(sig_is_good)
		return true;
	return logErrorRetFalse("A verifyShareUploadSig() failed!");
}

bool ClientHandlerSession::
writeShareList(ShareList const& store_me)
{
	std::string filename;
	std::string base_dir;
	if(!cur_client_store.getUserStoreDir(&base_dir))
		return logErrorRetFalse("Could not get user's base directory path to retrieve a ShareList.");
	filename = base_dir+"/"+SHARE_LIST_FILE_NAME;
	
	std::ofstream writer(filename, std::ofstream::binary);
	bool serialize_ok = store_me.SerializeToOstream(&writer);
	return serialize_ok;
}

bool addShareFile(KeyShare const& store_me)
{
	string orig_fp_base64 = base64_encode((uint8_t*)store_me.share_id().originator_fingerprint().c_str(),
								   store_me.share_id().originator_fingerprint().length());
	string owner_fp_base64 = base64_encode((uint8_t*)store_me.share_id().owner_fingerprint().c_str(),
								    store_me.share_id().owner_fingerprint().length());
	string enc_to_fp_base64 = base64_encode((uint8_t*)store_me.share_id().encrypted_to_fingerprint().c_str(),
									store_me.share_id().encrypted_to_fingerprint().length());
	
	std::string filename = g_stores_base_dirpath + "/keyshares/" + orig_fp_base64 + "-" + 
											owner_fp_base64 + "-" +
											enc_to_fp_base64;
	
	std::ofstream writer(filename, std::ofstream::binary);
	bool serialize_ok = store_me.SerializeToOstream(&writer);
	return serialize_ok;
}

bool revokeShareFile(ShareID const& to_revoke)
{
	string orig_fp_base64 = base64_encode((uint8_t*)to_revoke.originator_fingerprint().c_str(),
								   to_revoke.originator_fingerprint().length());
	string owner_fp_base64 = base64_encode((uint8_t*)to_revoke.owner_fingerprint().c_str(),
								    to_revoke.owner_fingerprint().length());
	string enc_to_fp_base64 = base64_encode((uint8_t*)to_revoke.encrypted_to_fingerprint().c_str(),
									to_revoke.encrypted_to_fingerprint().length());
	
	string full_filename = g_stores_base_dirpath + "/keyshares/" + orig_fp_base64 + "-" + 
											owner_fp_base64 + "-" +
											enc_to_fp_base64;
	//TODO securely erase file from hard drive
	if(0 == unlink(full_filename.c_str()) || errno == ENOENT)
		return true;
	else return false;
}





array<char, SHA_LENGTH_BYTES> computeShareListDigest(ShareList const& the_list)
{
	array<char, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	
	string timestamp_str = std::to_string(the_list.timestamp());
	SHA256_Update(&sha256, timestamp_str.c_str(), timestamp_str.length());
	string threshold_str = std::to_string(the_list.threshold());
	SHA256_Update(&sha256, threshold_str.c_str(), threshold_str.length());
	for(int i=0; i<the_list.recipients_size(); i++)
	{
		ShareList::ShareRecipient cur = the_list.recipients(i);
		if(cur.has_nickname())
			SHA256_Update(&sha256, cur.nickname().c_str(), cur.nickname().length());
		SHA256_Update(&sha256, cur.fingerprint().c_str(), cur.fingerprint().length());
		SHA256_Update(&sha256, (cur.initiator() ? "1" : "0"), 1);
	}
	SHA256_Final((uint8_t*)computed_digest.data(), &sha256);
	return computed_digest;
}

bool ClientHandlerSession::
verifyUploadedShareList(ShareList const& verify_me)
{
	array<char, SHA_LENGTH_BYTES> our_digest = computeShareListDigest(verify_me);
	
	vector<char> store_owner_pubkey;
	if(!cur_client_store.getStoreOwnerPubkey(&store_owner_pubkey))
		return logErrorRetFalse("verifyUploadedShareList() called with unitialized store context (no pubkey).");
	
	//Upload might come from either the store owner, or from some other person. So, try to verify 
	//both with cur_client_store.getStoreOwnerPubkey() and with client_supplied_pubkey (if present).
	bool sig_is_good = verifyRSASig((uint8_t*)store_owner_pubkey.data(), store_owner_pubkey.size(),
							  (uint8_t*)verify_me.signature().c_str(), verify_me.signature().length(),
							  (uint8_t*)our_digest.data(), our_digest.size());
	if(sig_is_good)
		return true;
	return logErrorRetFalse("A verifyUploadedShareList() failed!");
}

bool ClientHandlerSession::
handleShareUpload(ShareUpload const& msg)
{
	bool verification_good = verifyShareUploadSig(msg);
	
	ShareUploadResult response_content;
	response_content.set_verification_ok(verification_good);
	
	if(verification_good)
	{
		for(int i=0; i<msg.revoke_id_size(); i++)
			if(revokeShareFile(msg.revoke_id(i)))
				*(response_content.add_ids_revoked()) = msg.revoke_id(i);
		
		for(int i=0; i<msg.share_size(); i++)
			if(addShareFile(msg.share(i)))
				*(response_content.add_shares_added()) = msg.share(i).share_id();
	}
	
	//This upload includes a ShareList, which we should store (so long as the upload is from the store owner!)
	if(msg.has_list() && verifyUploadedShareList(msg.list()))
		writeShareList(msg.list());
	
	PAMRACMessage response;
	response.set_type(PAMRACMessage_Type_SHARE_UPLOAD_RESULT);
	*(response.mutable_share_upload_result()) = response_content;
	sendPAMRACMessage(response);
	return false;
}

} //end pamrac namespace
