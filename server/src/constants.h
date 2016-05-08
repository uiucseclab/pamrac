#ifndef _INCLGUARD_PAMRAC_CONSTANTS_H_
#define _INCLGUARD_PAMRAC_CONSTANTS_H_

//SHA-256
#define SHA_LENGTH_BYTES 32
#define SHA_LENGTH_STR "32"

//RSA 2048
#define RSA_PUBKEY_LEN_BYTES 256

#define KEY_FILE_PATH "/var/lib/pamrac/pamrac-server-key.key"
#define CERT_FILE_PATH "/var/lib/pamrac/pamrac-server-key.crt"
#define SHARE_LIST_FILE_NAME "this_user_share_list"

#define MAX_PROTOBUF_SIZE (8 * 1024 * 1024)

#define PAMRAC_FINGERPRINT_SIZE 16

#endif //_INCLGUARD_PAMRAC_CONSTANTS_H_
