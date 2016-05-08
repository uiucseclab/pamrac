#ifndef _INCLGUARD_PAMRAC_CLIENT_STORE_H_
#define _INCLGUARD_PAMRAC_CLIENT_STORE_H_

#include <unordered_map>
#include <string>
#include <vector>

#include "constants.h"

namespace pamrac {

//To be able to support multi-user servers, we need to know which of the server's users to work with.
//(Might not be the same as the user doing the request, e.g. a key share request).
//ClientStore is meant as a way to gather the necessary context together. Each ClientHandlerSession
//has a ClientStore, should initialize it after receiving the first message. (The message specifies 
//the fingerprint of the user in question, which ClientStore.load() uses to find their files).
class ClientStore
{
public:
	bool initialized() const {return _initialized;}
	
	//The ClientStore class caches these, so if this fingerprint was previously loaded, you get that
	//cached version. If not, it will try to read the files in the appropriate location.
	bool load(std::string const& user_fprint_binary);
	
	static bool createNew(std::string const& the_nickname, 
					std::string const& the_pubkey,
					std::string const& dl_secret);
	
	bool getStoreOwnerPubkey(std::vector<char>* gotten_key) const;
	bool getDownloadSecret(std::array<char, SHA_LENGTH_BYTES>* gotten_secret) const;
	//will be g_stores_base_dirpath+"/"+user pubkey fprint;
	bool getUserStoreDir(std::string* gotten_path) const;
	ClientStore() {_initialized = false;}
	
private:
	bool _initialized;
	//base_directory_path is: g_stores_base_dirpath+"/"+user pubkey fprint;
	std::string base_directory_path;
	std::string nickname;
	std::vector<char> pubkey;
	std::array<char, SHA_LENGTH_BYTES> download_secret;
	
	bool readNickname();
	bool readPubkey();
	bool readDownloadSecret();
	
	//TODO maybe have a MasterKeyPasswordedFile in here?
};

} //end namespace pamrac

#endif //_INCLGUARD_PAMRAC_CLIENT_STORE_H_ 

