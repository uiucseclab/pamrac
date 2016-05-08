#include <dirent.h>

#include <fstream>
#include <iostream>
#include <string>
using ::std::string;
#include <vector>
using ::std::vector;

#include "sha256.h"

#include "constants.h"
#include "globals.h"


void logError(string the_message)
{
	time_t tempTime;
	time(&tempTime);
	string time_string(ctime(&tempTime));
	int newline_ind = time_string.find_first_of('\n');
	if(newline_ind != string::npos)
		time_string.erase(newline_ind);
	string full_line = time_string+": "+the_message;
	
	if(g_logError_target_filename != string(""))
	{
		string full_line_newline = full_line + "\n";
		FILE* log_writer = fopen(g_logError_target_filename.c_str(), "at");
		fwrite(full_line_newline.c_str(), 1, full_line_newline.length(), log_writer);
		fclose(log_writer);
	}
	else
		std::cerr << full_line << std::endl;
}

bool logErrorRetFalse(string the_message)
{
	logError(the_message);
	return false;
}

void exitError(string the_message)
{
	logError(the_message);
	exit(1);
}

bool readRandomBytes(char* output, int bytes_to_read)
{
	FILE* urand_reader = fopen("/dev/urandom", "wb");
	if(!urand_reader)
	{
		logError("Could not read from /dev/urandom!");
		return false;
	}
	
	if(fread(output, 1, bytes_to_read, urand_reader) != bytes_to_read)
	{
		logError("Could not read enough bytes from /dev/urandom!");
		fclose(urand_reader);
		return false;
	}
	fclose(urand_reader);
	return true;
}

bool listDirectorysFiles(vector<string>* output, string dirpath)
{
	DIR* blobs_dir = opendir(dirpath.c_str());
	if(!blobs_dir)
		return logErrorRetFalse(dirpath+" does not exist!");
	
	struct dirent* cur_file;
	while( (cur_file = readdir(blobs_dir)) )
		output->push_back(std::string(cur_file->d_name));
	closedir(blobs_dir);
	return true;
}

bool fileContentsSHA256(std::array<char, SHA_LENGTH_BYTES>* output, string filepath)
{
	std::ifstream reader(filepath.c_str(), std::ifstream::binary);
	if(!reader.is_open())
		return logErrorRetFalse("Could not read from "+filepath+"!");
	
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	
	char buf[4096];
	reader.seekg(0, reader.end);
	int flen = reader.tellg();
	reader.seekg(0, reader.beg);
	int bytes_read = 0; 
	while(bytes_read < flen)
	{
		int cur_chunk_size = flen - bytes_read > 4096 ? 4096 : flen - bytes_read;
		reader.read(buf, cur_chunk_size);
		SHA256_Update(&sha256, buf, cur_chunk_size);
		bytes_read += cur_chunk_size;
	}
	reader.close();
	SHA256_Final((uint8_t*)output->data(), &sha256);	
	return true;
}



