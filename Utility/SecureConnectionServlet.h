//
// Created by gabriele on 17/01/21.
//

#ifndef FOUR_IN_A_ROW_SECURECONNECTIONSERVLET_H
#define FOUR_IN_A_ROW_SECURECONNECTIONSERVLET_H
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <chrono>

using namespace std;

#define NONCESIZE 16
#define TIMESTAMPSIZE 8
#define TIMEWINDOW 200 // in milliseconds
#define USERNAME_SIZE_MAX 30
#define SIGN_SIZE 256
#define MSGCODESIZE 1




#define CERT_SIZE 955
#define IV_LEN 16
#define GCM_TAG_LEN 16
#define KEY_SIZE 16
#define GMAC 1
#define GCM 2

class SecureConnectionServlet {
    EVP_PKEY * dh_params;
public:

    EVP_PKEY* generateNewDHKeys();
    unsigned char* deriveSecretDH(EVP_PKEY *privKey, EVP_PKEY *peer_key, size_t& secret_len);

    //AUTHENTICATION METHODS
    unsigned char* createHelloRequest(unsigned int header,string name, unsigned char*& nonce, EVP_PKEY* prvkey, size_t& len);
    bool checkHelloRequest(unsigned char *msg, size_t len, EVP_PKEY* pub_key, unsigned char*& nonce);
    unsigned char* createHelloResponse(unsigned int header,string name, X509* cert, EVP_PKEY* privkey, unsigned char*& my_nonce, unsigned char* noncepeer, EVP_PKEY* dh_key, size_t& len) ;
    bool checkHelloResponse(unsigned char *msg, size_t len, X509_STORE* store, EVP_PKEY* peer_pub_key, EVP_PKEY*& dh_peer_key, unsigned char* nonce, unsigned char *& nonceS);
    unsigned char* createHelloAcceptance(unsigned int header,string name, EVP_PKEY* prvKey, EVP_PKEY* dh_pub_key, unsigned char* noncePeer, size_t& len);
    bool checkHelloAcceptance(unsigned char *msg, size_t len, EVP_PKEY* pub_key, EVP_PKEY *&dh_peer_pub_key, unsigned char* nonce);
    unsigned char* createHelloRefuse(unsigned int header, string name, unsigned char* peer_nonce, X509* cert, EVP_PKEY* prvkey, size_t& len);
    bool checkHelloRefuse(unsigned char *msg, size_t len, X509_STORE* store, EVP_PKEY* peer_pub_key, unsigned char* my_nonce);
    //OTHER METHODS
    unsigned char* createAuthenticatedMsg(unsigned int header, string name, unsigned char* key, unsigned char*& iv, unsigned char* payload, size_t payload_len,size_t& len, unsigned int GCM_GMAC);
    bool checkAuthenticatedMsg(unsigned char *msg, size_t msg_len, unsigned char *key, unsigned char *&iv_peer, unsigned char*& pt, size_t& pt_len, unsigned int GCM_GMAC);

    unsigned char* serializeKeys(EVP_PKEY* keys, size_t& len);
    EVP_PKEY* deserializeKeys(unsigned char* key, size_t len);

    unsigned char* createErrorMessage(unsigned int errorHeader, string name);

    unsigned char* createRandomValue(size_t size);

    SecureConnectionServlet(){
        EVP_PKEY_CTX* ctx_params;
        ctx_params = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY_paramgen_init(ctx_params);
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx_params, NID_X9_62_prime256v1);
        EVP_PKEY_paramgen(ctx_params, &dh_params);
        EVP_PKEY_CTX_free(ctx_params);

    }

private:
    unsigned char* signObject(unsigned char* sign_cont , size_t sign_cont_len, EVP_PKEY* privkey, size_t& len);

    bool verifySignature(unsigned char* signature_content, size_t sign_cont_len,EVP_PKEY* pubkey , unsigned char* signature, size_t signature_len);
    bool verifyCertificate(X509* cert,X509_STORE* store );


    unsigned char* serializeCert(X509* cert, size_t& len);
    X509 * deserializeCert(unsigned char* cert_buf, size_t cert_size);
    EVP_PKEY* extractPubKeyFromCertificate(X509* cert);
    unsigned char* gcmEncrypt(unsigned char *pt, size_t pt_len,
                              size_t& ct_len,
                              unsigned char* key,
                              unsigned char* aad, size_t aad_len,
                              unsigned char* iv,
                              unsigned char*& tag);
    unsigned char* gcmDecrypt(unsigned char *ct, size_t ct_len,
                              size_t& pt_len,
                              unsigned char* key,
                              unsigned char* aad, size_t aad_len,
                              unsigned char* iv,
                              unsigned char* tag);
    unsigned char* gmacEncrypt(unsigned char* key,
                              unsigned char* aad, size_t aad_len,
                              unsigned char* iv);
    bool gmacDecrypt(unsigned char* key,
                               unsigned char* aad, size_t aad_len,
                               unsigned char* iv,
                               unsigned char*tag);
};


#endif //FOUR_IN_A_ROW_SECURECONNECTIONSERVLET_H
