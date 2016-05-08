#include <unistd.h>
#include <arpa/inet.h>

#include <string>
using ::std::string;
#include <vector>

#include "constants.h"

#include "utility.h"

#include "client_handler_session.h"

namespace pamrac {

bool ClientHandlerSession::
acceptSession(int client_socket)
{
	if(!(tls_session.loadCert(CERT_FILE_PATH) &&
		tls_session.loadKey(KEY_FILE_PATH) &&
		tls_session.acceptTLS(client_socket)))
	{
		logError("Failed to accept a TLS session after accepting a TCP connection; giving up on this connection.");
		close(client_socket);
		return false;
	}
	return true;
}

bool ClientHandlerSession::
doWholeConversation()
{
	bool keep_listening = true;
	PAMRACMessage client_message;
	do
	{
		if(!recvPAMRACMessageProtobuf(&client_message))
			return logErrorRetFalse("Client sent a garbled message; couldn't decode a protobuf message from it. Giving up on this connection.");
		
		//To be able to support multi-user servers, we need to know which of the server's users to work with.
		//(Might not be the same as the user doing the request, e.g. a key share request).
		//cur_client_store is meant as a way to gather the necessary context together.
		if(!cur_client_store.initialized())
		{
			if(!client_message.has_user_fingerprint())
				return logErrorRetFalse("Client failed to specify which user's store they want to work with.");
			if(!cur_client_store.load(client_message.user_fingerprint()))
				return logErrorRetFalse("Client asked to work with non-existent store, fingerprint: "+
									client_message.user_fingerprint());
		}
		
		//If they're supplying us with their public key (and haven't already supplied one), remember it.
		//(NOTE: this is NOT the "owner of the store" pubkey. It is, they are doing e.g. a share request,
		//so there is something they are signing, but we don't have their key.)
		if(client_message.has_client_pubkey() && client_supplied_pubkey.size() == 0)
			client_supplied_pubkey = std::vector<char>(client_message.client_pubkey().begin(), 
													client_message.client_pubkey().end());
		
		keep_listening = handlePAMRACMessage(client_message);
	} while(keep_listening);
	
	//NOTE: tls_session dtor handles all cleanup; ok to return whenever
	return true;
}


bool ClientHandlerSession::
sendPAMRACMessage(PAMRACMessage const& msg)
{
	string serialized;
	msg.SerializeToString(&serialized);
	
	uint32_t netorder_len = htonl(serialized.length());
	tls_session.sendTLS((const uint8_t*)&netorder_len, 4);
	
	int bytes_sent = 0;
	while(bytes_sent < serialized.length())
	{
		int cur_num_sent = tls_session.sendTLS((const uint8_t*)(serialized.c_str()+bytes_sent), 
								    (serialized.length() - bytes_sent > 16*1024 
								    ? 16*1024 : serialized.length() - bytes_sent));
		if(cur_num_sent <= 0)
			return false;
		bytes_sent += cur_num_sent;
	}
	return true;
}
		

bool ClientHandlerSession::
recvPAMRACMessageProtobuf(PAMRACMessage* recv_into)
{
	uint32_t netorder_len;
	tls_session.recvTLS((uint8_t*)&netorder_len, 4); //TODO timeout after a couple of seconds
	uint32_t message_len = ntohl(netorder_len);
	
	if(message_len > MAX_PROTOBUF_SIZE)
		return false;
	
	uint8_t* recv_buf = new uint8_t[message_len];
	int bytes_recvd = 0;
	while(bytes_recvd < message_len)
	{
		int cur_num_recvd = tls_session.recvTLS(&recv_buf[bytes_recvd], 
									message_len - bytes_recvd > 16*1024 
									? 16*1024 : message_len - bytes_recvd);
		if(cur_num_recvd <= 0)
		{
			delete[] recv_buf;
			return false;
		}
		bytes_recvd += cur_num_recvd;
	}
	bool success = recv_into->ParseFromString(string((const char*)recv_buf, message_len));
	delete[] recv_buf;
	return success;
}

string msgTypeToString(PAMRACMessage_Type type)
{
	switch(type)
	{
		case PAMRACMessage_Type_INIT_BLOB_UPLOAD: return string("InitBlobUpload");
		case PAMRACMessage_Type_INIT_SHARE_UPLOAD: return string("InitShareUpload");
		case PAMRACMessage_Type_INIT_SHARE_REQUEST: return string("InitShareRequest");
		case PAMRACMessage_Type_INIT_SHARE_LIST_REQUEST: return string("InitShareListRequest");
		//TODO the rest of these (so far unused)
		default: return string("!!!UKNOWN PAMRAC MESSAGE TYPE!!!");
	}
}

bool ClientHandlerSession::
sendNonceResponse(PAMRACMessage_Type type_responding_to)
{
	if(!nonce.generate())
		return logErrorRetFalse("Failed to generate a nonce for a client's "
							+msgTypeToString(type_responding_to)+" message.");
	NonceResponse nonce_response;
	nonce_response.set_nonce(string(nonce.peek().data(), nonce.peek().size()));
	
	PAMRACMessage response;
	switch(type_responding_to)
	{
	case PAMRACMessage_Type_INIT_BLOB_UPLOAD:
		response.set_type(PAMRACMessage_Type_BLOB_UPLOAD_NONCE);
		break;
	case PAMRACMessage_Type_INIT_SHARE_UPLOAD:
		response.set_type(PAMRACMessage_Type_SHARE_UPLOAD_NONCE);
		break;
	case PAMRACMessage_Type_INIT_SHARE_REQUEST:
		response.set_type(PAMRACMessage_Type_SHARE_REQUEST_NONCE);
		break;
	case PAMRACMessage_Type_INIT_SHARE_LIST_REQUEST:
		response.set_type(PAMRACMessage_Type_SHARE_LIST_REQUEST_NONCE);
		break;
	default:
		return logErrorRetFalse("sendNonceResponse() called on an unanticipated message type: "+msgTypeToString(type_responding_to));
	}
	*(response.mutable_nonce_response()) = nonce_response;
	
	return sendPAMRACMessage(response); //(true if nothing breaks)
}

//Returns true if we should expect another message from the client in response
//to what this function sent them.
bool ClientHandlerSession::
handlePAMRACMessage(PAMRACMessage const& msg)
{
	switch(msg.type())
	{
	case PAMRACMessage_Type_INIT_BLOB_REQUEST: 
		if(!msg.has_init_blob_request())
			return logErrorRetFalse("Error: received a protobuf message claiming to be an InitBlobRequest, but with an empy init_blob_request field!");
		else
			return handleInitBlobRequest(msg.init_blob_request());
			
	case PAMRACMessage_Type_BLOB_REQUEST:
		if(!msg.has_blob_request())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a BlobRequest, but with an empy blob_request field!");
		else
			return handleBlobRequest(msg.blob_request());
		
		
		
	case PAMRACMessage_Type_INIT_BLOB_UPLOAD:
		return sendNonceResponse(PAMRACMessage_Type_INIT_BLOB_UPLOAD); //no message content!
	case PAMRACMessage_Type_INIT_SHARE_UPLOAD:
		return sendNonceResponse(PAMRACMessage_Type_INIT_SHARE_UPLOAD); //no message content!	
	case PAMRACMessage_Type_INIT_SHARE_REQUEST:
		return sendNonceResponse(PAMRACMessage_Type_INIT_SHARE_REQUEST); //no message content!
	case PAMRACMessage_Type_INIT_SHARE_LIST_REQUEST:
		return sendNonceResponse(PAMRACMessage_Type_INIT_SHARE_LIST_REQUEST); //no message content!
	
	case PAMRACMessage_Type_BLOB_UPLOAD:
		if(!msg.has_blob_upload())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a BlobUpload, but with an empy blob_upload field!");
		else
			return handleBlobUpload(msg.blob_upload());

	case PAMRACMessage_Type_SHARE_UPLOAD:
		if(!msg.has_share_upload())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a ShareUpload, but with an empy share_upload field!");
		else
			return handleShareUpload(msg.share_upload());

	case PAMRACMessage_Type_SHARE_REQUEST:
		if(!msg.has_share_request())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a ShareRequest, but with an empy share_request field!");
		else
			return handleShareRequest(msg.share_request());

	case PAMRACMessage_Type_SHARE_LIST_REQUEST:
		if(!msg.has_share_list_request())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a ShareListRequest, but with an empy share_list_request field!");
		else
			return handleShareListRequest(msg.share_list_request());
		
	case PAMRACMessage_Type_CONNECT_TO_NEW_STORE:
		if(!msg.has_connect_to_new_store())
			return logErrorRetFalse("Error: received a protobuf message claiming to be a ShareListRequest, but with an empy share_list_request field!");
		else
			return handleConnectNewStore(msg.connect_to_new_store());

	default:
		return logErrorRetFalse("Warning: received a (valid) protobuf message with an unknown type!");
	}
}

void ClientHandlerSession::Nonce::
set(std::array<char, SHA_LENGTH_BYTES> const& input)
{
	nonce_active = true;
	_nonce = input;
}
bool ClientHandlerSession::Nonce::
generate()
{
	if(!readRandomBytes(_nonce.data(), _nonce.size()))
		return false;
	nonce_active = true; return true;
}

bool ClientHandlerSession::Nonce::
pop(std::array<char, SHA_LENGTH_BYTES>* output)
{
	if(!nonce_active) return false;
	nonce_active = false;
	*output = _nonce; return true;
}

} //end namespace pamrac

