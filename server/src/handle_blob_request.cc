#include <string>
using ::std::string;
#include <array>
using ::std::array;
#include <vector>
using ::std::vector;

#include <fstream>
#include <unordered_map>

#include "sha256.h"

#include "constants.h"
#include "utility.h"

#include "client_handler_session.h"

namespace pamrac {

bool ClientHandlerSession::
checkDownloadSecretProof(string const& their_nonce, string const& their_proof)
{
	if(their_nonce.length() != SHA_LENGTH_BYTES)
		return logErrorRetFalse("Client's BlobRequest's nonce was "+std::to_string(their_nonce.length())
								+" bytes (expected "+SHA_LENGTH_STR+").");
	if(their_proof.length() != SHA_LENGTH_BYTES)
		return logErrorRetFalse("Client's BlobRequest's proof was "+std::to_string(their_proof.length())
								+" bytes (expected "+SHA_LENGTH_STR+").");
								
	array<char, SHA_LENGTH_BYTES> our_nonce;
	if(!nonce.pop(&our_nonce))
		return logErrorRetFalse("Client sent a BlobRequest when we didn't have a nonce saved.");
		
	if(memcmp(our_nonce.data(), their_nonce.c_str(), SHA_LENGTH_BYTES))
		return logErrorRetFalse("Client sent a BlobRequest with a nonce not matching our saved nonce.");
	
	array<uint8_t, SHA_LENGTH_BYTES> our_proof;
	array<char, SHA_LENGTH_BYTES> the_dl_secret;
	if(!cur_client_store.getDownloadSecret(&the_dl_secret))
		return false;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, the_dl_secret.data(), the_dl_secret.size());
	SHA256_Update(&sha256, our_nonce.data(), our_nonce.size());
	SHA256_Final(our_proof.data(), &sha256);
	
	if(memcmp(our_proof.data(), their_proof.c_str(), SHA_LENGTH_BYTES))
		return logErrorRetFalse("Client sent a BlobRequest with a proof different from what we computed.");
	return true;
}

bool parseBlobFile(BlobFile* output, string filepath)
{
	std::ifstream reader(filepath.c_str(), std::ifstream::binary);
	if(!reader.is_open())
		return logErrorRetFalse("Could not read from "+filepath+"!");
	if(!output->ParseFromIstream(&reader))
		return logErrorRetFalse("Failed to parse a BlobFile from "+filepath+"!");
	return true;
}

void ClientHandlerSession::
addBlobFileToResponseIfChanged(BlobResponse* our_response_msg, 
						std::unordered_map<string, array<char, SHA_LENGTH_BYTES> > const& their_hashes, 
						string filename_not_path)
{
	std::string store_path;
	cur_client_store.getUserStoreDir(&store_path);
	
	if(their_hashes.find(filename_not_path) == their_hashes.end())
	{
		BlobResponse_NamedBlobFile named_blob_to_add;
		BlobFile inner_blob;
		if(parseBlobFile(&inner_blob, store_path+"/blobs/"+filename_not_path))
		{
			*(named_blob_to_add.mutable_blob()) = inner_blob;
			*(named_blob_to_add.mutable_name()) = filename_not_path;
			*(our_response_msg->add_new_blobs()) = named_blob_to_add;
		}
		return;
	}
	
	array<char, SHA_LENGTH_BYTES> cur_their_hash = their_hashes.find(filename_not_path)->second;
	array<char, SHA_LENGTH_BYTES> cur_our_hash;
	if(!fileContentsSHA256(&cur_our_hash, store_path+"/blobs/"+filename_not_path))
		return;
	if(cur_their_hash != cur_our_hash)
	{
		BlobResponse_NamedBlobFile named_blob_to_add;
		BlobFile inner_blob;
		if(parseBlobFile(&inner_blob, store_path+"/blobs/"+filename_not_path))
		{
			*(named_blob_to_add.mutable_blob()) = inner_blob;
			*(named_blob_to_add.mutable_name()) = filename_not_path;
			*(our_response_msg->add_new_blobs()) = named_blob_to_add;
		}
	}
}

bool ClientHandlerSession::
handleBlobRequest(pamrac::BlobRequest const& msg)
{
	if(!cur_client_store.initialized())
		return logErrorRetFalse("handleBlobRequest() called with unitialized client store context.");
	
	if(!checkDownloadSecretProof(msg.proof_nonce(), msg.downloadsecret_proof()))
		return false;
	
	//Gather up the "we already have these" hashes they sent.
	std::unordered_map<string, array<char, SHA_LENGTH_BYTES> > their_hashes;
	for(int i=0; i<msg.cached_blobs_size(); i++)
	{
		BlobRequest_BlobHash cur_hash = msg.cached_blobs(i);
		array<char, SHA_LENGTH_BYTES> insert_hash;
		memcpy(insert_hash.data(), cur_hash.blob_hash().c_str(), insert_hash.size());
		their_hashes[cur_hash.blob_name()] = insert_hash;
	}
	
	std::string store_path;
	if(!cur_client_store.getUserStoreDir(&store_path))
		return false;
	
	//For each file in blobs/ that does not match a hash they sent,
	//add that file to the response.
	BlobResponse our_response_msg;	
	vector<string> all_files;
	if(!listDirectorysFiles(&all_files, store_path+"/blobs"))
		return false;
	for(auto const& each_filename_no_path : all_files)
		addBlobFileToResponseIfChanged(&our_response_msg, their_hashes, each_filename_no_path);
	
	PAMRACMessage response;
	response.set_type(PAMRACMessage_Type_BLOB_RESPONSE);
	*(response.mutable_blob_response()) = our_response_msg;
	sendPAMRACMessage(response);
	
	return false;
}

} //end pamrac namespace
