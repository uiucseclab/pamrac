#include <string>
using ::std::string;
#include <fstream>
#include <vector>

#include "sha256.h"

#include "globals.h"
#include "utility.h"

#include "client_handler_session.h"

namespace pamrac {

bool computeFilesHashXOR(std::array<char, SHA_LENGTH_BYTES>* output, string blobs_dirname)
{
	std::vector<string> all_files;
	if(!listDirectorysFiles(&all_files, blobs_dirname))
		return false;
	
	*output = {0};
	for(auto const& each_filename : all_files)
	{
		std::array<char, SHA_LENGTH_BYTES> cur_hash;
		if(!fileContentsSHA256(&cur_hash, blobs_dirname+"/"+each_filename))
			return false;
		for(int i=0; i<SHA_LENGTH_BYTES; i++)
			(*output)[i] = cur_hash[i] ^ (*output)[i];
	}
	return true;
}

bool ClientHandlerSession::
handleInitBlobRequest(InitBlobRequest const& msg)
{
	string their_xor = msg.all_hash_xor();
	if(their_xor.length() != SHA_LENGTH_BYTES)
		return logErrorRetFalse("Error: an InitBlobRequest sent an all_hash_xor of "
				+std::to_string(their_xor.length())+" bytes. (Expected "+SHA_LENGTH_STR+").");
	
	std::array<char, SHA_LENGTH_BYTES> our_xor;
	if(!computeFilesHashXOR(&our_xor, g_stores_base_dirpath+"/blobs"))
		return false;
	//if their hash XOR matches ours, then they don't need to request.
	if(memcmp(their_xor.c_str(), our_xor.data(), SHA_LENGTH_BYTES) == 0)
	{
		InitBlobResponse response_content;
		response_content.set_xor_matches(true);
		
		PAMRACMessage response;
		response.set_type(PAMRACMessage_Type_INIT_BLOB_RESPONSE);
		*(response.mutable_init_blob_response()) = response_content;
		sendPAMRACMessage(response);
		
		return false;
	}
	else //hash XOR doesn't match; they need to request
	{
		if(!nonce.generate())
			return logErrorRetFalse("Failed to generate a nonce for an InitBlobResponse.");
		
		InitBlobResponse response_content;
		response_content.set_nonce(string(nonce.peek().data(),nonce.peek().size()));
		response_content.set_xor_matches(false);
		
		PAMRACMessage response;
		response.set_type(PAMRACMessage_Type_INIT_BLOB_RESPONSE);
		*(response.mutable_init_blob_response()) = response_content;
		
		return sendPAMRACMessage(response); //(true if nothing breaks)
	}
}

} //end pamrac namespace
