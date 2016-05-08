#include <dirent.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
using std::cerr;
using std::endl;

//TODO: scrypt is hardcoded to use the non-sse2 version (because that's all that
//works on my laptop). 
#include "crypto_scrypt.h"
#include "insecure_memzero.h"
#include "aes.h"
#include "base64.h"
#include "pamrac.pb.h"

#include "conversion_interface.h"

void secure_zero_c_array(void* zero_me, int array_size)
{
	volatile unsigned char* p = (volatile unsigned char*)zero_me;
	while(array_size--)
		*p++ = 0;
}

void secure_zero_std_string(std::string* zero_me)
{
	//TODO but apparently this isn't enough, uggghhhhhhh
	for(int i=0; i<zero_me->length(); i++)
		(*zero_me)[i] = 0;
}

PAMRACConversionInterface::
PAMRACConversionInterface()
{
	password_set = false;
	directory_loaded = false;
}

void PAMRACConversionInterface::
setPassword(std::string the_password)
{
	PASSWORD = the_password;
	password_set = true;
}

PAMRACConversionInterface::PAMRACBlob::
PAMRACBlob()
{
	version = -1;
	has_salt = false;
	init_vec_populated = false;
	modified = false;
	retrievable = BLOB_IRRETRIEVABLE;
}

void PAMRACConversionInterface::PAMRACBlob::
selectInnerKey(uint8_t* inner_key,	std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key, 
			std::string const& master_password)
{
	if(!has_salt && retrievable == BLOB_IRRETRIEVABLE)
	{
		FILE* dev_urandom = fopen("/dev/urandom", "rb");
		if(!dev_urandom)
		{
			cerr << "ERROR! Cannot open /dev/urandom." << endl;
			return;
		}
		for(int i=0;i<key_derivation_salt.size();i++)
			key_derivation_salt[i] = (uint8_t)fgetc(dev_urandom);
		fclose(dev_urandom);
		
		has_salt = true;
	}
	
	if(has_salt) //ciphertext encrypted by password
	{
		crypto_scrypt((const uint8_t*)master_password.c_str(), master_password.length(), 
				    key_derivation_salt.data(), key_derivation_salt.size(), 
					PAMRAC_SCRYPT_N, PAMRAC_SCRYPT_r, PAMRAC_SCRYPT_p, inner_key, AES_KEYLEN_BYTES);
	}
	else //ciphertext encrypted by MASTER
		memcpy(inner_key, master_key.data(), AES_KEYLEN_BYTES);
}

//NOTE filename_to_parse should be the salted filename, i.e. what the file is actually stored
//under in the filesystem.
bool PAMRACConversionInterface::PAMRACBlob::
parseBlobfile(std::string filename_to_parse, std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key,
		    std::string const& password)
{
	std::ifstream blobfile(filename_to_parse, std::ios::binary);
	
	pamrac::BlobFile blob;
	if(!blob.ParseFromIstream(&blobfile))
	{
		cerr << "WARNING! File " << filename_to_parse 
			<< "\nis not a valid protocol buffer of type BlobFile!" << endl;
		return false;
	}
	
	std::string ciphertext = blob.inner_blob_ciphertext();
	version = blob.version();
	
	//Transfer IV from the vector of the protobuf class to the std::array of this class.
	for(int i=0; i<init_vec.size() && i<blob.aes_init_vector().size(); i++)
		init_vec[i] = blob.aes_init_vector()[i];
	init_vec_populated = true;
	
	//Transfer salt, if present, from protobuf's vector to our std::array.
	if((has_salt = blob.has_salt()))
		for(int i=0; i<key_derivation_salt.size() && i<blob.salt().size(); i++)
			key_derivation_salt[i] = blob.salt()[i];
	//Having the key derivation salt implies the data is encrypted with a key derived
	//from PASSWORD, which the retrieval process cannot get.
	retrievable = has_salt ? BLOB_IRRETRIEVABLE : BLOB_IS_RETRIEVABLE;
	
	
	
	
	
	//Need a non-const, plain old C array copy of the IV because aes_crypt_cbc() wants to modify it.
	uint8_t temp_init_vec[AES_KEYLEN_BYTES];
	memcpy(temp_init_vec, getInitVec().data(), AES_KEYLEN_BYTES);
	uint8_t inner_key[AES_KEYLEN_BYTES];
	selectInnerKey(inner_key, master_key, password);
	
	
	uint8_t* inner_plaintext = new uint8_t[ciphertext.length()];
	aes_context AESdec;
	aes_setkey_dec(&AESdec, inner_key, AES_KEYLEN_BYTES*8);
	aes_crypt_cbc(&AESdec, AES_DECRYPT, ciphertext.length(), temp_init_vec, 
			    (const unsigned char*)ciphertext.c_str(), inner_plaintext);
	
	
	
	
	
	pamrac::InnerBlob inner_blob;
	//NOTE: we need to use this 2-argument string ctor in case there are '\0' bytes!
	if(!inner_blob.ParseFromString(std::string((char*)inner_plaintext, ciphertext.length())))
	{
		cerr << "WARNING! Failed to parse an InnerBlob from the plaintext decrypted from inside "
			<< "the BlobFile protocol buffer in " << filename_to_parse << endl;
		
		insecure_memzero(inner_plaintext, ciphertext.length());
		insecure_memzero(inner_key, AES_KEYLEN_BYTES);
		insecure_memzero(&AESdec, sizeof(aes_context));
		//TODO uh... how to securely erase anything that might be in inner_blob?
		delete[] inner_plaintext;
		return false;
	}
	
	name = inner_blob.filename();
	
	//For each item in the inner blob, set values[key]=value
	for(int i=0; i<inner_blob.fields_size(); i++)
		values[inner_blob.fields(i).name()] = inner_blob.fields(i).value();
	
	insecure_memzero(inner_plaintext, ciphertext.length());
	insecure_memzero(inner_key, AES_KEYLEN_BYTES);
	insecure_memzero(&AESdec, sizeof(aes_context));
	//TODO uh... how to securely erase anything that might be in inner_blob?
	delete[] inner_plaintext;
	return true;
}

std::array<uint8_t, AES_KEYLEN_BYTES> PAMRACConversionInterface::PAMRACBlob::
getInitVec()
{
	if(init_vec_populated)
		return init_vec;
	
	FILE* dev_urandom = fopen("/dev/urandom", "rb");
	if(!dev_urandom)
	{
		cerr << "ERROR! Cannot open /dev/urandom." << endl;
		std::array<uint8_t, AES_KEYLEN_BYTES> whoops = {123};
		return whoops;
	}
	for(int i=0;i<init_vec.size();i++)
		init_vec[i] = (uint8_t)fgetc(dev_urandom);
	fclose(dev_urandom);
	
	init_vec_populated = true;
	return init_vec;
}


std::string deriveFilename(std::string const& name, std::array<uint8_t, AES_KEYLEN_BYTES> const& file_name_salt)
{
	unsigned char hash_buf[AES_KEYLEN_BYTES];
	
	crypto_scrypt((const unsigned char*)name.c_str(), name.length(), 
				file_name_salt.data(), file_name_salt.size(), 
				PAMRAC_SCRYPT_N, PAMRAC_SCRYPT_r, PAMRAC_SCRYPT_p, 
				hash_buf, AES_KEYLEN_BYTES);
	
	std::string base_64_out = base64_encode(hash_buf, AES_KEYLEN_BYTES);
	
	insecure_memzero(hash_buf, name.length()+file_name_salt.size());
	
	return base_64_out;
}

//Writes this blob to its appropriate file (filename derived from site name and file_name_salt).
//First populates an InnerBlob, then serializes and encrypts that to become the inner_blob_ciphertext
//field of a BlobFile, which is finally serialized into the target file.
bool PAMRACConversionInterface::PAMRACBlob::
writeBlobfile(std::string const& blobdir_path, std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key, 
			std::array<uint8_t, AES_KEYLEN_BYTES> const& file_name_salt, std::string const& master_password)
{
	//Populate the InnerBlob: filename, and values.
	pamrac::InnerBlob inner_blob;
	inner_blob.set_filename(name);
	for(auto const& each : values)
	{
		pamrac::InnerBlob_KeyValue* new_kv = inner_blob.add_fields();
		new_kv->set_name(each.first);
		new_kv->set_value(each.second);
	}
	
	
	//Now that we have our InnerBlob all populated, we serialize it and encrypt the result,
	//which we will fill the BlobFile's inner_blob_ciphertext field with.
	std::string plaintext_inner;
	inner_blob.SerializeToString(&plaintext_inner);
	
	//Need to pad up to whatever block size we're using.
	while(plaintext_inner.length() % AES_KEYLEN_BYTES != 0)
		plaintext_inner += "\0";
	
	
	
	uint8_t* cipertext_result = new uint8_t[plaintext_inner.length()];
	
	//Need a non-const, plain old C array copy of the IV because aes_crypt_cbc() wants to modify it.
	uint8_t temp_init_vec[AES_KEYLEN_BYTES];
	memcpy(temp_init_vec, getInitVec().data(), AES_KEYLEN_BYTES);
	uint8_t inner_key[AES_KEYLEN_BYTES];
	selectInnerKey(inner_key, master_key, master_password);
	
	aes_context AESenc;
	aes_setkey_enc(&AESenc, inner_key, AES_KEYLEN_BYTES*8);
	//NOTE: plaintext_inner.length() assumed to now be a multiple of AES_KEYLEN_BYTES!
	aes_crypt_cbc(&AESenc, AES_ENCRYPT, plaintext_inner.length(), temp_init_vec,
			    (const unsigned char*)plaintext_inner.c_str(), cipertext_result);
	
	
	//Now that we have our inner_blob_ciphertext, we can populate that, as well as all the other fields.
	pamrac::BlobFile blob_file;
	//NOTE: we need to use this 2-argument string ctor in case there are '\0' bytes!
	blob_file.set_inner_blob_ciphertext(std::string((char*)cipertext_result, plaintext_inner.length()));
	blob_file.set_aes_init_vector(std::string((char*)getInitVec().data(), getInitVec().size()));
	blob_file.set_version(version);
	if(has_salt)
		blob_file.set_salt(std::string((char*)key_derivation_salt.data(), key_derivation_salt.size()));
	
	std::string derived_filename = deriveFilename(name, file_name_salt);
	std::ofstream blob_outfile(blobdir_path+"/"+derived_filename, std::ios::binary);
	if(!blob_outfile.is_open())
	{
		cerr << "ERROR! Could not write blob file to " << blobdir_path+"/"+derived_filename << endl;
		delete[] cipertext_result;
		secure_zero_std_string(&plaintext_inner);
		insecure_memzero(inner_key, AES_KEYLEN_BYTES);
		insecure_memzero(&AESenc, sizeof(aes_context));
		return false;
	}
	blob_file.SerializeToOstream(&blob_outfile);
	blob_outfile.close();
	
	delete[] cipertext_result;
	//TODO secure zero inner_blob
	secure_zero_std_string(&plaintext_inner);
	insecure_memzero(inner_key, AES_KEYLEN_BYTES);
	insecure_memzero(&AESenc, sizeof(aes_context));
	return true;
}

void PAMRACConversionInterface::
insertFromBlobFile(std::string filename)
{
	PAMRACBlob new_blob;
	if(!new_blob.parseBlobfile(filename, MASTER_key, PASSWORD))
	{
		cerr << "Failed to parse an irretrievable BlobFile from " << filename << endl;
		return;
	}
	
	if(sites.find(new_blob.name) != sites.end())
	{
		cerr << "WARNING! Somehow read a blobfile with a site name we already have a blob for!\n"
			<< "Will take the one with the higher version number." << endl;
		if(sites[new_blob.name].version >= new_blob.version)
			return;
	}
	sites[new_blob.name] = new_blob;
}

//Gets filenamesalt and MASTER out of the masterkey_passworded file.
bool PAMRACConversionInterface::
loadMasterKeyPassworded()
{
	std::ifstream encrypted_file_reader(base_directory_path+"/masterkey_passworded", std::ios::binary);
	pamrac::MasterKeyPasswordedFile mkpf;
	if(!mkpf.ParseFromIstream(&encrypted_file_reader))
	{
		cerr << "Couldn't read a MasterKeyPasswordedFile protocol buffer from "+base_directory_path+"/masterkey_passworded" << endl;
		return false;
	}
	
	//Derive key from PASSWORD and this file's salt
	uint8_t inner_key[AES_KEYLEN_BYTES];
	crypto_scrypt((const uint8_t*)PASSWORD.c_str(), PASSWORD.length(), 
				(const uint8_t*)mkpf.salt().c_str(), mkpf.salt().length(), 
				PAMRAC_SCRYPT_N, PAMRAC_SCRYPT_r, PAMRAC_SCRYPT_p, inner_key, AES_KEYLEN_BYTES);
	
	
	uint8_t* inner_plaintext = new uint8_t[mkpf.inner_ciphertext().size()];
	//Need a non-const, plain old C array copy of the IV because aes_crypt_cbc() wants to modify it.
	uint8_t temp_init_vec[AES_KEYLEN_BYTES];
	memcpy(temp_init_vec, mkpf.aes_init_vector().c_str(), AES_KEYLEN_BYTES);
	
	aes_context AESenc;
	aes_setkey_enc(&AESenc, inner_key, AES_KEYLEN_BYTES*8);
	aes_crypt_cbc(&AESenc, AES_DECRYPT, mkpf.inner_ciphertext().size(), temp_init_vec,
			    (const uint8_t*)mkpf.inner_ciphertext().c_str(), inner_plaintext);
	
	
	pamrac::InnerPassworded crown_jewels;
	if(!crown_jewels.ParseFromString(std::string((char*)inner_plaintext)))
	{
		cerr << "Couldn't parse the InnerPassworded protocol buffer inside the ciphertext of "+base_directory_path+"/masterkey_passworded" << endl;
		insecure_memzero(inner_plaintext, mkpf.inner_ciphertext().size());
		delete[] inner_plaintext;
		//TODO secure zero crown_jewels
		insecure_memzero(inner_key, AES_KEYLEN_BYTES);
		insecure_memzero(&AESenc, sizeof(aes_context));
		return false;
	}
	
	for(int i=0; i<filenamesalt.size() && i<crown_jewels.filenamesalt().size(); i++)
		filenamesalt[i] = crown_jewels.filenamesalt()[i];
	for(int i=0; i<MASTER_key.size() && i<crown_jewels.master_key().size(); i++)
		MASTER_key[i] = crown_jewels.master_key()[i];
	
	//TODO secure zero crown_jewels
	insecure_memzero(inner_key, AES_KEYLEN_BYTES);
	insecure_memzero(&AESenc, sizeof(aes_context));
	insecure_memzero(inner_plaintext, mkpf.inner_ciphertext().size());
	delete[] inner_plaintext;
	
	return true;
}

bool PAMRACConversionInterface::
loadPAMRACDirectory(std::string base_dir_path)
{
	base_directory_path = base_dir_path;
	if(!password_set)
	{
		cerr << "Tried to loadPAMRACDirectory() without password set!" << endl;
		return false;
	}
	
	if(!loadMasterKeyPassworded())
		return false;
	
	struct dirent* cur_file;
	DIR* blobs_dir = opendir((base_directory_path+"/blobs").c_str());
	if(!blobs_dir)
	{
		cerr << base_directory_path << "/blobs does not exist!" << endl;
		return false;
	}
	while( (cur_file = readdir(blobs_dir)) )
		insertFromBlobFile(base_directory_path+"/blobs/"+cur_file->d_name);
	closedir(blobs_dir);
	
	directory_loaded = true;
	return true;
}

std::vector<std::string> PAMRACConversionInterface::getAllSiteNames()
{
	std::vector<std::string> ret;
	for(auto it = sites.cbegin(); it != sites.cend(); ++it)
		ret.push_back(it->first);
	return ret;
}

bool PAMRACConversionInterface::
setSiteValues(std::string site_name, std::unordered_map<std::string, std::string> const& values, 
			int new_ver, IgnoreVersion ignore_ver, BlobRetrievability retrble)
{
	if(sites.find(site_name) != sites.end())
	{
		if(ignore_ver == IGNORE_VERSION_NO && new_ver <= sites.find(site_name)->second.version)
			return false;
		sites[site_name].version = new_ver;
		sites[site_name].values = values;
		sites[site_name].modified = true;
		sites[site_name].retrievable = retrble;
		return true;
	}
	
	PAMRACBlob new_blob;
	new_blob.version = new_ver;
	new_blob.values = values;
	new_blob.name = site_name;
	new_blob.modified = true;
	new_blob.retrievable = retrble;
	sites[site_name] = new_blob;
	return true;
}

BlobRetrievability PAMRACConversionInterface::
getRetrievability(std::string site_name)
{
	if(sites.find(site_name) == sites.end())
		return BLOB_IS_RETRIEVABLE;
	return sites[site_name].retrievable;
}

int PAMRACConversionInterface::
getSiteVersion(std::string site_name)
{
	if(sites.find(site_name) == sites.end())
		return -1;
	return sites[site_name].version;
}

bool PAMRACConversionInterface::
getSiteValues(std::string site_name, std::unordered_map<std::string, std::string>* values)
{
	if(sites.find(site_name) == sites.end())
		return false;
	*values = sites[site_name].values;
	return true;
}

void PAMRACConversionInterface::
commit()
{
	for(auto& each : sites)
		if(each.second.modified)
		{
			if(each.second.writeBlobfile(base_directory_path+"/blobs", MASTER_key, filenamesalt, PASSWORD))
				each.second.modified = false;
		}
}

PAMRACConversionInterface::
~PAMRACConversionInterface()
{
	secure_zero_std_string(&PASSWORD);
	insecure_memzero(MASTER_key.data(), MASTER_key.size());
	insecure_memzero(filenamesalt.data(), filenamesalt.size());
}

PAMRACConversionInterface::PAMRACBlob::
~PAMRACBlob()
{
	//TODO secure zero values
	secure_zero_std_string(&name);
}
