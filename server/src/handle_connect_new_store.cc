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
#include "globals.h"
#include "utility.h"

#include "client_store.h"
#include "client_handler_session.h"

namespace pamrac {

bool ClientHandlerSession::
handleConnectNewStore(pamrac::ConnectToNewStore const& msg)
{
	NewStoreConnectResult our_response_msg;
	PAMRACMessage response;
	response.set_type(PAMRACMessage_Type_NEW_STORE_CONNECT_RESULT);
	
	//HACK TODO
	if(g_joining_passcodes.find(msg.passcode()) == g_joining_passcodes.end() && msg.passcode() != "HACKALICE"
		&& msg.passcode() != "HACKBOB" && msg.passcode() != "HACKCAROL"	)
	{
		our_response_msg.set_success(false);
		*(response.mutable_new_store_connect_result()) = our_response_msg;
		sendPAMRACMessage(response);
	
		return logErrorRetFalse("Warning: a client tried to join with non-active passcode "+msg.passcode());
	}
	
	g_joining_passcodes["HACKALICE"] = "alice";
	g_joining_passcodes["HACKBOB"] = "bob";
	g_joining_passcodes["HACKCAROL"] = "carol";
	
	string new_nickname = g_joining_passcodes[msg.passcode()];
	bool created_successfully = ClientStore::createNew(new_nickname, msg.public_key(), msg.download_secret());
	if(created_successfully)
		g_joining_passcodes.erase(msg.passcode());
	our_response_msg.set_success(created_successfully);
	
	*(response.mutable_new_store_connect_result()) = our_response_msg;
	sendPAMRACMessage(response);
	return false;
}

} //end pamrac namespace
