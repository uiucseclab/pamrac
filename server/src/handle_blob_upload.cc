#include <array>
using ::std::array;
#include <string>
using ::std::string;

#include <fstream>

#include "sha256.h"
#include "crypto.h"

#include "utility.h"
#include "client_handler_session.h"

namespace pamrac {

//Computes SHA256(hashed_filename~blob.[IFPRESENT(salt)~toString(version)~initvec~ciphertext]~nonce)
array<uint8_t, SHA_LENGTH_BYTES> computeBlobFileDigest(string const& hashed_filename, BlobFile const& blob, array<char, SHA_LENGTH_BYTES> const& our_nonce)
{
	array<uint8_t, SHA_LENGTH_BYTES> computed_digest;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, hashed_filename.c_str(), hashed_filename.length());
	if(blob.has_salt())
		SHA256_Update(&sha256, blob.salt().c_str(), blob.salt().length());
	string version_string = std::to_string(blob.version());
	SHA256_Update(&sha256, version_string.c_str(), version_string.length());
	SHA256_Update(&sha256, blob.aes_init_vector().c_str(), blob.aes_init_vector().length());
	SHA256_Update(&sha256, blob.inner_blob_ciphertext().c_str(), blob.inner_blob_ciphertext().length());
	SHA256_Update(&sha256, our_nonce.data(), our_nonce.size());
	SHA256_Final(computed_digest.data(), &sha256);
	return computed_digest;
}

bool ClientHandlerSession::
verifyBlobUploadSig(BlobUpload const& msg)
{
	array<char, SHA_LENGTH_BYTES> our_nonce;
	if(!nonce.pop(&our_nonce))
		return logErrorRetFalse("verifyBlobUploadSig() was called when session did not have a nonce saved!");
	if(our_nonce.size() != msg.nonce().length() || memcmp(msg.nonce().c_str(), our_nonce.data(),
																our_nonce.size()))
	{
		return logErrorRetFalse("verifyBlobUploadSig(): their nonce does not match the nonce we saved!");
	}
	
	//sig should be of:
	//(hashed_filename~blob.[IFPRESENT(salt)~toString(version)~initvec~ciphertext]~nonce)
	array<uint8_t, SHA_LENGTH_BYTES> our_digest = computeBlobFileDigest(msg.hashed_filename(), 
														msg.blob(), our_nonce);
	
	std::vector<char> store_owner_pubkey;
	if(!cur_client_store.getStoreOwnerPubkey(&store_owner_pubkey))
		return logErrorRetFalse("verifyBlobUploadSig() called with unitialized store context (no pubkey).");
	
	if(verifyRSASig((const uint8_t*)store_owner_pubkey.data(), store_owner_pubkey.size(),
				(const uint8_t*)msg.signature().c_str(), msg.signature().length(),
				(const uint8_t*)our_digest.data(), our_digest.size()))
	{
		return true;
	}
	else
		return logErrorRetFalse("A verifyShareUploadSig() failed!");
}

bool writeBlobFile(BlobFile const& to_write, string filepath)
{
	std::ofstream writer(filepath.c_str(), std::ofstream::binary);
	if(!writer.is_open())
		return logErrorRetFalse("Could not open "+filepath+" for writing!");
	if(to_write.SerializeToOstream(&writer))
		return logErrorRetFalse("Failed to serialize a BlobFile to "+filepath+"!");
	return true;
}

bool ClientHandlerSession::
handleBlobUpload(pamrac::BlobUpload const& msg)
{
	std::string store_path;
	if(!cur_client_store.getUserStoreDir(&store_path))
		return false;
	
	bool verification_good = verifyBlobUploadSig(msg);
	
	BlobUploadResult response_content;
	response_content.set_verification_ok(verification_good);
	
	if(verification_good)
	{
		BlobFile current_blob;
		//1) Failure to parse means no need to worry about versions!
		//2) If we did parse a good existing file, then the uploaded blob must have higher version#.
		if(!parseBlobFile(&current_blob, store_path+"/blobs/"+msg.hashed_filename())
			|| current_blob.version() < msg.blob().version())
		{
			bool file_write_succeeded = writeBlobFile(msg.blob(), msg.hashed_filename());
			response_content.set_upload_successful(file_write_succeeded);
		}
		else //Tell them we're rejecting due to version. (Include our current version#.)
		{
			response_content.set_upload_successful(false);
			response_content.set_server_version(current_blob.version());
		}
	}

	PAMRACMessage response;
	response.set_type(PAMRACMessage_Type_BLOB_UPLOAD_RESULT);
	*(response.mutable_blob_upload_result()) = response_content;
	sendPAMRACMessage(response);
	return false;
}

} //end pamrac namespace
