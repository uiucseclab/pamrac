#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <array>
#include <memory>
#include <thread>
#include <fstream>

#include "polarssl/ssl.h"
#include "polar_tls_server.h"

#include "constants.h"
#include "globals.h"
#include "utility.h"

#include "client_handler_session.h"

//daemonize! thank you Devin Watson: http://www.netzmafia.de/skripten/unix/linux-daemon-howto.html
void daemonize()
{
	//Our process ID and Session ID
	pid_t pid, sid;

	//Fork off the parent process
	pid = fork();
	if(pid < 0)
		exit(EXIT_FAILURE);
	//If we got a good PID, then we can exit the parent process.
	if(pid > 0)
		exit(EXIT_SUCCESS);

	//Change the file mode mask
	umask(0);

	//Create a new SID for the child process
	sid = setsid();
	if(sid < 0)
		exit(EXIT_FAILURE);

	//Change the current working directory
	if((chdir("/")) < 0)
		exit(EXIT_FAILURE);

	//Close out the standard file descriptors
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
}

void readOrCreateSecretOrDie(std::array<char, SHA_LENGTH_BYTES>* download_secret)
{
	FILE* download_secret_reader = fopen("/var/lib/pamrac/downloadsecret", "rb");
	if(!download_secret_reader)
	{
		if(!readRandomBytes(download_secret->data(), download_secret->size()))
			exitError("Fatal error while trying to get random bytes from /dev/urandom.");
		
		FILE* secret_writer = fopen("/var/lib/pamrac/downloadsecret", "wb");
		if(!secret_writer)
			exitError("Could not write to /var/lib/pamrac/downloadsecret");
		if(fwrite(download_secret->data(), 1, SHA_LENGTH_BYTES, secret_writer) < SHA_LENGTH_BYTES)
			exitError("Could not write all data to /var/lib/pamrac/downloadsecret");
		fclose(secret_writer);	
	}
	else
	{
		if(fread(download_secret->data(), 1, SHA_LENGTH_BYTES, download_secret_reader) != SHA_LENGTH_BYTES)
			exitError("Could not read enough bytes from /var/lib/pamrac/downloadsecret!");
		fclose(download_secret_reader);
	}
}

bool tryReadOrCreateDownloadSecret(std::array<char, SHA_LENGTH_BYTES>* download_secret, 
							std::string const& secretfile_path)
{
	std::ifstream secret_reader(secretfile_path, std::ifstream::binary);
	if(!secret_reader.is_open())
	{
		if(!readRandomBytes(download_secret->data(), download_secret->size()))
			return logErrorRetFalse("Fatal error while trying to get random bytes from /dev/urandom.");
		
		std::ofstream secret_writer(secretfile_path, std::ofstream::binary);
		if(!secret_writer.is_open())
			return logErrorRetFalse("Could not write to "+secretfile_path);
		secret_writer.write(download_secret->data(), download_secret->size());
	}
	else
	{
		secret_reader.read(download_secret->data(), download_secret->size());
		if(!secret_reader)
			return logErrorRetFalse("Could not read enough bytes from "+secretfile_path);
	}
	return true;
}


void connectionThread(int client_socket)
{
	pamrac::ClientHandlerSession client_session;
	if(client_session.acceptSession(client_socket))
		client_session.doWholeConversation();
}


void acceptConnections(uint16_t listen_port)
{
	int listener_socket, accepted_socket;

	if(net_bind(&listener_socket, NULL, listen_port) != 0)
		exitError("Couldn't bind+listen port "+std::to_string(listen_port)+" on any network interface!");
	
	while(1)
	{
		//I think if accept() actually fails, it's almost always going to be the type where every
		//call is going to immediately return with the same error, so rather than trying again and
		//again and generating a 10GB logError file, just exit.
		if(net_accept(listener_socket, &accepted_socket, NULL) != 0)
			exitError("Failed to accept a connection.");
		
		std::thread(connectionThread, accepted_socket).detach();
	}
}


int main(int argc, char** argv)
{
	//Load settings: base dir location, listen_port
	std::string listen_port_str;
	std::ifstream settings_reader("/var/lib/pamrac/config");
	if(!settings_reader.is_open()
		|| !std::getline(settings_reader, g_stores_base_dirpath)
		|| !std::getline(settings_reader, listen_port_str))
	{
		exitError("Failed to read settings from /var/lib/pamrac/config!");
	}
	settings_reader.close();
	
	//server must have a certificate + key
	if(access(KEY_FILE_PATH, R_OK) != 0)
		exitError("Server's key file ("+std::string(KEY_FILE_PATH)+") is missing.");
	if(access(CERT_FILE_PATH, R_OK) != 0)
		exitError("Server's cert file ("+std::string(CERT_FILE_PATH)+") is missing.");
	
	if(argc > 1 && !strcmp(argv[1], "daemon"))
		daemonize();
	
	/*TODO struct sigaction siggy;
	memset(&siggy, 0, sizeof(struct sigaction));
	siggy.sa_handler = gracefulExit;
	sigaction(SIGTERM, &siggy, NULL);
	sigaction(SIGINT, &siggy, NULL);*/
	
	
	//TODO acceptConnections(listen_port);
	acceptConnections((uint16_t)std::stoi(listen_port_str));
}

