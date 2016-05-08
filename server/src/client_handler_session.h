#ifndef _INCLGUARD_PAMRAC_CLIENT_HANDLER_SESSION_H_ 
#define _INCLGUARD_PAMRAC_CLIENT_HANDLER_SESSION_H_

#include <string>
#include <vector>

#include "pamrac.pb.h"
#include "polar_tls_server.h"

#include "client_store.h"

namespace pamrac {

class ClientHandlerSession
{
public:
	//Returns true for success; for false, just give up on this ClientHandlerSession object
	//(this function will close the TCP connection in that case).
	bool acceptSession(int client_socket);
	bool doWholeConversation();
	
	ClientHandlerSession() {}
	
	
	
private:
	//Returns false if something went wrong; in that case the caller should abandon this session.
	bool sendPAMRACMessage(PAMRACMessage const& msg);
	
	//Returns false if something went wrong; in that case the caller should abandon this session.
	bool recvPAMRACMessageProtobuf(PAMRACMessage* recv_into);
	
	//Returns true if we should expect another message from the client in response
	//to what this function sent them.
	bool handlePAMRACMessage(PAMRACMessage const& msg);
	
	//One of these will be called by handlePAMRACMessage(), according to message type.
	//Return value is same as for handlePAMRACMessage(): whether to expect another message.
	bool handleInitBlobRequest(InitBlobRequest const& msg);
	bool handleBlobRequest(BlobRequest const& msg);
	bool handleInitBlobUpload(void); //no message content!
	bool handleBlobUpload(BlobUpload const& msg);
	bool handleInitShareUpload(void); //no message content!
	bool handleShareUpload(ShareUpload const& msg);
	bool handleInitShareRequest(void); //no message content!
	bool handleShareRequest(ShareRequest const& msg);
	bool handleInitShareListRequest(void); //no message content!
	bool handleShareListRequest(ShareListRequest const& msg);
	bool handleConnectNewStore(ConnectToNewStore const& msg);
	
	//For when you want to respond a message with just a nonce (a NonceResponse).
	bool sendNonceResponse(PAMRACMessage_Type type_responding_to);
	
	
	
	
	//For handleBlobRequest():
	bool checkDownloadSecretProof(std::string const& their_nonce, std::string const& their_proof);
	void addBlobFileToResponseIfChanged
		(BlobResponse* our_response_msg, 
		std::unordered_map<std::string, std::array<char, SHA_LENGTH_BYTES> > const& their_hashes, 
		std::string filename_not_path);
	
	//For handleBlobUpload():
	bool verifyBlobUploadSig(BlobUpload const& msg);
	
	//For handleShareListRequest():
	bool verifyShareListRequestSig(ShareListRequest const& msg);
	bool parseShareListFile(ShareList* response_content);
	
	//For handleShareRequest():
	bool verifyShareRequestSig(ShareRequest const& msg);
	
	//For handleShareUpload():
	bool writeShareList(ShareList const& store_me);
	bool verifyShareUploadSig(ShareUpload const& msg);
	bool verifyUploadedShareList(ShareList const& verify_me);
	
	
	PolarTLSServer tls_session;
	class Nonce
	{
	public:
		//Get the nonce. After this function, this object will consider
		//itself unitialized; further pop()s will fail until generate() called again.
		bool pop(std::array<char, SHA_LENGTH_BYTES>* output);
		
		//Suggest that you only use this directly after generate()!
		//Will silently return unitialized garbage if not active.
		std::array<char, SHA_LENGTH_BYTES> const& peek() { return _nonce; }
		
		void set(std::array<char, SHA_LENGTH_BYTES> const& input);
		bool generate();
		Nonce() {nonce_active = false;}
	private:
		std::array<char, SHA_LENGTH_BYTES> _nonce;
		bool nonce_active;
	};
	Nonce nonce;
	ClientStore cur_client_store;
	
	//If they supply us with their public key, we keep it here. (NOTE: this is NOT 
	//the "owner of the store" pubkey. Rather, the connected user is doing e.g. a share 
	//request, so there is something they are signing, but we don't have their key.)
	std::vector<char> client_supplied_pubkey;
};

bool parseBlobFile(BlobFile* output, std::string filepath);

} //end namespace pamrac

#endif //_INCLGUARD_PAMRAC_CLIENT_HANDLER_SESSION_H_

