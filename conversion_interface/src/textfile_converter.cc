#include <fstream>
#include <iostream>
using std::cerr;
using std::cout;
using std::cin;
using std::endl;
#include <cstring>
#include <string>
using std::string;
#include <vector>
using std::vector;
#include <unordered_map>
using std::unordered_map;

#include <unistd.h>
#include <termios.h>

#include "conversion_interface.h"

//=Give the converter a path to a directory.
//=The converter reads every text file in the directory (and descends recursively).
//=A file named filename OR filename.txt will be interpreted as 1 blob, with sitename 'filename'.
//=One non-blank line in a file = 1 key+value. Key+value are separated by a colon. 
//	Lines without colons are concatenated and stored under a special key called *MISC_INFO*
//=If there is a field called *PAMRAC_VERSION*, then its value (should be an integer) is the version number.
//=If there is a field called *PAMRAC_IRRETRIEVABLE* and its value is not 'false', 
// then the blob is irretrievable.
//=If converter running in PAMRAC=>foreign mode:
//	If the PAMRAC installation that the converter was pointed at contains any blobs with the same sitename and 
//	a lower version, the textfile converter will report them, and not write any changes.
//=If converter running in foreign=>PAMRAC mode:
//	If any of the foreign textfiles have a version number, and that version is lower than PAMRAC's
//   corresponding blob, the textfile converter will report them and not write any changes.

void inputHiddenString(string* the_string)
{
	termios temp;
	tcgetattr(STDIN_FILENO, &temp);
	termios hidden_term = temp;
	hidden_term.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &hidden_term);
	std::getline(cin, *the_string);
	tcsetattr(STDIN_FILENO, TCSANOW, &temp);
}

//Given a target data directory structure, asks a perl script to recursively collect all of the filepaths in it 
//and print them for us, separated by newlines. Make a CommandEntry out of each one, and return them all.
vector<string> processDataDir(string dir_name)
{
	vector<string> all_items;
	
	FILE* perl_pipe = popen((string("perl readdir.pl ")+dir_name).c_str(), "r");
	
	size_t line_getter_len = 500;
	char* line_getter = (char*)malloc(line_getter_len);
	memset(line_getter, 0, line_getter_len);
	while(getline(&line_getter, &line_getter_len, perl_pipe) > 0)
	{
		if(strchr(line_getter, '\n'))
			*strchr(line_getter, '\n') = 0;
		if(strlen(line_getter) > 0)
			all_items.push_back(string(line_getter));
	}
	pclose(perl_pipe);
	free(line_getter);
	
	return all_items;
}

bool readSiteFile(string* site_name,
			std::unordered_map<string, string>* values,
			int* version,
			IgnoreVersion* ignore_ver,
			BlobRetrievability* retrievable,
			string const& filename)
{
	std::ifstream reader;
	reader.open(filename);
	if(!reader.is_open())
	{
		reader.open(filename+".txt");
		if(!reader.is_open())
			return false;
	}
	
	*site_name = filename;
	//If filename ends in .txt, cut it off for the site name.
	if(site_name->rfind(".txt") == site_name->length() - 4)
		site_name->erase(site_name->length() - 4);
	
	//default values:
	*retrievable = BLOB_IS_RETRIEVABLE;
	*ignore_ver = IGNORE_VERSION_YES;
	*version = -1;
	(*values)["*MISC_INFO*"] = "";
	
	for(string line; std::getline(reader, line); )
	{
		if(line.find(":") == string::npos)
		{
			(*values)["*MISC_INFO*"] += line + ", ";
		}
		else if(line.find("*PAMRAC_VERSION*") != string::npos)
		{
			*version = std::stoi(line.substr(line.find(":")+1));
			*ignore_ver = IGNORE_VERSION_NO;
		}
		else if(line.find("*PAMRAC_IRRETRIEVABLE*") != string::npos)
		{
			*retrievable = (line.find("false") == string::npos 
						? BLOB_IRRETRIEVABLE
						: BLOB_IS_RETRIEVABLE );
		}
		else
		{
			string field_name = line.substr(0, line.find(":"));
			string field_val = line.substr(line.find(":"));
			field_val = field_val.substr(field_val.find_first_not_of(" "), 
								    field_val.find_last_not_of(" ")+1);
			(*values)[field_name] = field_val;
		}
	}
	return true;
}

void fromPAMRACToForeign(PAMRACConversionInterface pamrac, string textfiles_dir)
{
	std::vector<std::string> all_sites = pamrac.getAllSiteNames();
	for(auto const& cur_sitename : all_sites)
	{
		string site_name_dummy;
		std::unordered_map<string, string> values_dummy;
		int version;
		IgnoreVersion ignore_ver;
		BlobRetrievability retrievable_dummy;
		readSiteFile(&site_name_dummy, &values_dummy, &version, 
				   &ignore_ver, &retrievable_dummy, textfiles_dir+"/"+cur_sitename);
		
		if(pamrac.getSiteVersion(cur_sitename) < version && ignore_ver != IGNORE_VERSION_YES)
		{
			cerr << "Warning: text file for " << cur_sitename << " has a higher version than the "
				<< "corresponding PAMRAC blob. Skipping this one." << endl;
		}
		else
		{
			std::unordered_map<string, string> site_values;
			if(!pamrac.getSiteValues(cur_sitename, &site_values))
			{
				cerr << "Warning: No blob for " << cur_sitename 
					<< ", despite its being listed. Skipping. " << endl;
				continue;
			}
			
			std::ofstream writer(textfiles_dir+"/"+cur_sitename+".txt", std::ofstream::out);
			if(!writer.is_open())
			{
				cerr << "Warning: could not write to " << cur_sitename << ".txt. Skipping." << endl;
				continue;
			}
			for(auto const& each : site_values)
				writer << each.first << ": " << each.second << "\n";
			
			writer << "*PAMRAC_IRRETRIEVABLE*: " << 
				(pamrac.getRetrievability(cur_sitename) == BLOB_IS_RETRIEVABLE ? "true\n" : "false\n")
				<< "*PAMRAC_VERSION*: " << pamrac.getSiteVersion(cur_sitename) << endl;
		}
	}
}

void fromForeignToPAMRAC(PAMRACConversionInterface pamrac, string textfiles_dir)
{
	//recursively read all the files in the text file dir
	vector<string> files_list = processDataDir(textfiles_dir);
	
	bool overwrite_pamrac_ok = true;
	for(auto const& cur_filename : files_list)
	{
		string site_name;
		std::unordered_map<string, string> values;
		int version;
		IgnoreVersion ignore_ver;
		BlobRetrievability retrievable;
		readSiteFile(&site_name, &values, &version, &ignore_ver, &retrievable, cur_filename);
		
		if(!pamrac.setSiteValues(site_name, values, version, ignore_ver, retrievable))
		{
			overwrite_pamrac_ok = false;
			cerr << "Error: " << site_name 
				<< " has a higher version than the text file you are converting from. "
				<< "Will not overwrite the PAMRAC store." << endl;
			break;
		}
	}
	if(overwrite_pamrac_ok)
		pamrac.commit();
}

int main(int argc, char** argv)
{
	if(argc != 4 || (strcmp(argv[1], "frompamrac") && strcmp(argv[1], "topamrac")))
	{
		cerr << "usage: "<<argv[0]<<"<frompamrac|topamrac> foreign_textfiles_dir pamrac_dir" << endl;
		return 1;
	}
	
	bool from_pamrac = (strcmp(argv[1], "frompamrac") == 0);
	
	string the_PASSWORD;
	cout << "Input master password: ";
	inputHiddenString(&the_PASSWORD);
	
	PAMRACConversionInterface pamrac;
	pamrac.setPassword(the_PASSWORD);
	
	//NOTE this function fails if there isn't a masterkey_passworded, and blobs/. This is ok: you should
	//use the PAMRAC server itself to init a new store; this converter won't do it for you.
	if(!pamrac.loadPAMRACDirectory(string(argv[3])))
	{
		cerr << "Error: failed to load a PAMRAC store from" << argv[3] << ". If no other error messages were printed "
			<< "indicating that something else is wrong, then that directory is probably just not initialized as a PAMRAC store. Will initialize our own." << endl;
		pamrac.initPAMRACDirectory(string(argv[3]));
		//TODO? return 1;
	}
	
	if(from_pamrac)
		fromPAMRACToForeign(pamrac, argv[2]);
	else
		fromForeignToPAMRAC(pamrac, argv[2]);
}
