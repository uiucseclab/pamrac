#ifndef __INCLGUARD_PAMRAC_CONVERSION_INTERFACE_H_
#define __INCLGUARD_PAMRAC_CONVERSION_INTERFACE_H_

#include <vector>
#include <string>
#include <unordered_map>

#define PAMRAC_SCRYPT_N (2*2*2*2 * 2*2*2*2 * 2*2*2*2 * 2)
#define PAMRAC_SCRYPT_r 8
#define PAMRAC_SCRYPT_p 1

#define AES_KEYLEN_BYTES 32

enum IgnoreVersion
{
	IGNORE_VERSION_NO = 0,
	IGNORE_VERSION_YES = 1,
};

enum BlobRetrievability
{
	BLOB_IS_RETRIEVABLE = 0,
	BLOB_IRRETRIEVABLE = 1,
};

//Programmatic representation of a user's PAMRAC archive. Can either be read from an existing
//PAMRAC archive on disk (setPassword(), then loadPAMRACDirectory() ), or can be populated 
//from another source (using setSiteValues()). Can write/update a PAMRAC archive (just call
//commit() ), or can provide you with the data to write to your own format (enumerate sites
//with getAllSiteNames(), and then call getSiteValues() on each site).

class PAMRACConversionInterface
{
public:
	//The user's PASSWORD, so that we can access all of this stuff.
	void setPassword(std::string the_password);
	
	//Goes into this directory expecting blobs/, masterkey_passworded, etc to be present.
	//Uses PASSWORD to open everything up, and populate the sites unordered_map.
	bool loadPAMRACDirectory(std::string base_dir_path);
	bool initPAMRACDirectory(std::string base_dir_path);
	
	//Returns the names of all of the sites that currently have values stored for them. Any one of these
	//can be used as the site_name argument for the get()s below.
	std::vector<std::string> getAllSiteNames();
	
	//Adds a new site with this name and fieldname:value mapping, if one does not already exist with 
	//this name. Replaces the fieldname:value map for this site with the one provided, if existing state 
	//is a lower version, or ignore_ver == IGNORE_VERSION_YES.
	//Returns false if an existing site was left untouched due to version.
	bool setSiteValues(std::string site_name, std::unordered_map<std::string, std::string> const& values, 
				    int new_ver, IgnoreVersion ignore_ver, BlobRetrievability retrble);
	
	//Returns false and leaves 'unordered_map values' alone if site_name does not exist.
	bool getSiteValues(std::string site_name, std::unordered_map<std::string, std::string>* values);
	
	//Returns -1 if site_name does not exist.
	int getSiteVersion(std::string site_name);
	
	BlobRetrievability getRetrievability(std::string site_name);
	
	//Write all changes made by setSiteValues(). Those changes are written to disk only if this 
	//function is called.
	void commit();
	
	PAMRACConversionInterface();
	//TODO secure zeroing on dtor
	~PAMRACConversionInterface();
private:
	
	class PAMRACBlob
	{
	public:
		bool modified;
		int version;
		std::unordered_map<std::string, std::string> values;
		std::string name;
		
		std::array<uint8_t, AES_KEYLEN_BYTES> init_vec; //TODO can be private? check
		bool init_vec_populated;
		std::array<uint8_t, AES_KEYLEN_BYTES> key_derivation_salt;
		bool has_salt;
		
		BlobRetrievability retrievable;
		
		//returns true if successful
		bool parseBlobfile(std::string filename_to_parse, 
					    std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key, 
						 std::string const& password);
		
		bool writeBlobfile(std::string const& blobdir_path, 
				    std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key, 
				    std::array<uint8_t, AES_KEYLEN_BYTES> const& file_name_salt,
				    std::string const& master_password);
		
		PAMRACBlob();
		~PAMRACBlob();
		
	private:
		std::array<uint8_t, AES_KEYLEN_BYTES> getInitVec();
		
		void selectInnerKey(uint8_t* inner_key, std::array<uint8_t, AES_KEYLEN_BYTES> const& master_key, 
					std::string const& master_password);
	};
	
	void insertFromBlobFile(std::string filename);
	bool writeBlobfile(PAMRACBlob const& blob);
	bool loadMasterKeyPassworded();
	
	std::unordered_map<std::string, PAMRACBlob> sites;
	std::string PASSWORD;
	std::array<uint8_t, AES_KEYLEN_BYTES> MASTER_key;
	std::array<uint8_t, AES_KEYLEN_BYTES> filenamesalt;
	std::string base_directory_path;
	
	bool password_set;
	bool directory_loaded;
};


#endif //__INCLGUARD_PAMRAC_CONVERSION_INTERFACE_H_
