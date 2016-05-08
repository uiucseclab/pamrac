#include <sys/stat.h>
#include <cstring>

#include <fstream>
using ::std::ofstream;
using ::std::ifstream;
#include <string>
using ::std::string;
#include <vector>
using ::std::vector;
#include <array>
using ::std::array;

#include "base64.h"
#include "crypto.h"

#include "globals.h"
#include "utility.h"
#include "client_store.h"

namespace pamrac {

bool ClientStore::
load(string const& user_fprint_binary)
{
	string user_fprint_str = base64_encode((uint8_t*)user_fprint_binary.c_str(),
									    user_fprint_binary.length());
	if(g_all_hosted_clients.find(user_fprint_str) != g_all_hosted_clients.end())
	{
		*this = g_all_hosted_clients[user_fprint_str];
		return true;
	}
	
	base_directory_path = g_stores_base_dirpath+"/"+user_fprint_str;
	ifstream pubkey_reader(base_directory_path+"/this_store_user_pubkey", ifstream::binary);
	if(!readPubkey() || !readNickname() || !readDownloadSecret())
		return logErrorRetFalse(user_fprint_str+" is not a fully initialized store in "+base_directory_path+" on this server.");
	
	_initialized = true;
	g_all_hosted_clients[user_fprint_str] = *this;
	return true;
}

bool ClientStore::
createNew(string const& the_nickname, 
		string const& the_pubkey,
		string const& dl_secret)
{
	string base_directory_path = g_stores_base_dirpath + "/" + base64FingerprintFromDERPubkey(the_pubkey);
	
	if(0 != mkdir(base_directory_path.c_str(), S_IRWXU) && errno != EEXIST)
		return logErrorRetFalse(string("Error creating new store. Could not mkdir base directory: ") +
							strerror(errno));
	
	ofstream nick_writer(base_directory_path + "/this_store_user_nickname");
	if(nick_writer)
		nick_writer << the_nickname << std::endl;
	else
		return logErrorRetFalse("Error creating new store. Could not write to this_store_user_nickname.");
	
	ofstream pubkey_writer(base_directory_path + "/this_store_user_pubkey", ofstream::binary);
	if(pubkey_writer)
		pubkey_writer.write(the_pubkey.c_str(), the_pubkey.length());
	else
		return logErrorRetFalse("Error creating new store. Could not write to this_store_user_pubkey.");
	
	ofstream dlsecret_writer(base_directory_path + "/downloadsecret", ofstream::binary);
	if(dlsecret_writer)
		dlsecret_writer.write(dl_secret.c_str(), dl_secret.length());
	else
		return logErrorRetFalse("Error creating new store. Could not write to downloadsecret.");
	return true;
}

bool ClientStore::
getDownloadSecret(array<char, SHA_LENGTH_BYTES>* gotten_secret) const
{
	if(!_initialized)
		return logErrorRetFalse("getDownloadSecret() called on an uninitialized ClientStore!");
	*gotten_secret = download_secret;
	return true;
}

bool ClientStore::
getStoreOwnerPubkey(vector<char>* gotten_key) const
{
	if(!_initialized)
		return logErrorRetFalse("getStoreOwnerPubkey() called on an uninitialized ClientStore!");
	*gotten_key = pubkey;
	return true;
}

bool ClientStore::
getUserStoreDir(string* gotten_path) const
{
	if(!_initialized)
		return logErrorRetFalse("getUserStoreDir() called on an uninitialized ClientStore!");
	*gotten_path = base_directory_path;
	return true;
}

bool ClientStore::
readDownloadSecret()
{
	if(base_directory_path.length() == 0)
		return logErrorRetFalse("tryReadDownloadSecret() called with base_directory_path not set!");
	
	ifstream reader(base_directory_path+"/downloadsecret", ifstream::binary);
	if(!reader.is_open())
		return logErrorRetFalse(base_directory_path+"/downloadsecret does not exist.");
	if(!reader.read(download_secret.data(), download_secret.size()))
		return logErrorRetFalse("Could not read enough bytes from "+base_directory_path+"/downloadsecret");
	return true;
}

bool ClientStore::
readNickname()
{
	if(base_directory_path.length() == 0)
		return logErrorRetFalse("readNickname() called with base_directory_path not set!");
	
	ifstream reader(base_directory_path+"/this_store_user_nickname");
	if(!reader.is_open())
		return logErrorRetFalse(base_directory_path+"/this_store_user_nickname does not exist.");
	std::getline(reader, nickname);
	return true;
}

bool ClientStore::
readPubkey()
{
	if(base_directory_path.length() == 0)
		return logErrorRetFalse("readPubkey() called with base_directory_path not set!");
	
	ifstream reader(base_directory_path+"/this_store_user_pubkey", ifstream::binary);
	if(!reader.is_open())
		return logErrorRetFalse(base_directory_path+"/this_store_user_pubkey does not exist.");
	std::streamsize flen = reader.tellg();
	if(flen < 10) //basic, very liberal sanity check: definitely no such thing as a 9 byte public key.
		return logErrorRetFalse("PUB KEY TOO SMALL TODO BETTER WAY"); //TODO actually we should be actually parsing the file into some sort of polarssl key struct. Then we just check if the parse failed.
	reader.seekg(0, std::ios::beg);
	pubkey.reserve(flen);
	if(!reader.read(pubkey.data(), flen))
		return logErrorRetFalse("Could not read all of "+base_directory_path+"/this_store_user_pubkey");
	return true;
}


} //end namespace pamrac

