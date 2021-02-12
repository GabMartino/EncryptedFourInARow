//
// Created by gabriele on 17/01/21.
//

#include "SecureConnectionServlet.h"
/**
 * This function return a pointer of unsigned char to an allocated memory
 * which contain a certain number of random bytes.
 * The number of bytes is specified by the param size
 *
 * @param size
 * @return unsigned char* to allocated memory
 */
unsigned char* SecureConnectionServlet::createRandomValue(size_t size){
    unsigned char* randomValue = (unsigned char*)malloc(size);
    if(!randomValue){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    if(!RAND_bytes(randomValue, size)){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return randomValue;

}

/**
 *************************************************************************************
 *
 *                      MESSAGE CREATION METHODS
 *
 * ***********************************************************************************
 */

//************************** HELLO REQUEST MESSAGE - CREATION AND CHECKING METHODS*****

/**
 * This function create a message of type
 *              Header, ID, nonceID, Sid(H(HEADER, ID, nonceID))
 * Only the hash of the values will be sign. Hash Algorithm = SHA-256
 *
 * @param name, this string represent the ID on USERNAME_SIZE_MAX bytes
 * @param nonce, null pointer in which will be inserted random bytes
 * @param prvkey, private key used to sign HEADER, ID, nonceId
 * @param len, reference in which will be inserted the length of the message in bytes
 * @return pointer to the allocated message
 */
unsigned char * SecureConnectionServlet::createHelloRequest(unsigned int header, string name, unsigned char*& nonce, EVP_PKEY* prvkey, size_t& len) {


    //HEADER
    char* head = (char*)malloc(MSGCODESIZE*sizeof(uint8_t));
    if(!head){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    //unsigned char* header = new unsigned char ;
    *head = (char)header;

    //ID
    char* ID = (char*)malloc(USERNAME_SIZE_MAX*sizeof(uint8_t));
    if(!ID){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memset(ID,0, USERNAME_SIZE_MAX);
    strcpy(ID, name.c_str());

    //NONCE
    if(nullptr == (nonce = createRandomValue(NONCESIZE))) {free(head); free(ID); return nullptr;}
    unsigned int sign_cont_len = MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE + TIMESTAMPSIZE;
    unsigned char* sign_cont = (unsigned char*)malloc(sign_cont_len*sizeof(uint8_t));
    if(!sign_cont){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    using namespace std::chrono;
    // Get current time with precision of milliseconds
    auto now = time_point_cast<milliseconds>(system_clock::now());
    // sys_milliseconds is type time_point<system_clock, milliseconds>
    using sys_milliseconds = decltype(now);
    // Convert time_point to signed integral type
    uint64_t integral_duration = now.time_since_epoch().count();

    memcpy(sign_cont, head, MSGCODESIZE);
    memcpy(&sign_cont[MSGCODESIZE], ID, USERNAME_SIZE_MAX);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX], nonce, NONCESIZE);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE], &integral_duration, TIMESTAMPSIZE);

    size_t signatureLen = 0;
    unsigned char* signature;
    if(nullptr == ( signature = signObject(sign_cont,sign_cont_len, prvkey, signatureLen))){ free(nonce); free(head); free(ID); free(sign_cont);return nullptr;}

    len = sign_cont_len + signatureLen;
    unsigned char* msg = (unsigned char*)malloc(sign_cont_len + signatureLen);
    if(!msg){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(msg, sign_cont, sign_cont_len);
    memcpy(&msg[sign_cont_len], signature, signatureLen);

    free(head);
    free(ID);
    free(sign_cont);
    free(signature);
    return msg;

}
/**
 * This function checks the validity of the message created with createHelloRequest(...)
 * It's supposed to be called when the ID of the sender has been already identified,
 * and so his public key retrieved from a Database
 *
 * @param msg, pointer to the whole message
 * @param len, lenght of the while message
 * @param pub_key, publickey of the User who suppose to be the sender
 * @param nonce, null point in which the nonce will be saved
 * @return
 */
bool SecureConnectionServlet::checkHelloRequest(unsigned char *msg, size_t len, EVP_PKEY* pub_key, unsigned char*& nonce_peer) {


    unsigned char* signature_content; size_t sgn_cont_size = len - SIGN_SIZE;
    if(nullptr == ( signature_content = (unsigned char*)malloc(sgn_cont_size))) return false;

    unsigned char* signature; size_t sgn_size = SIGN_SIZE;
    if(nullptr == ( signature = (unsigned char* )malloc(sgn_size))) {free(signature_content); return false;}

    memcpy(signature_content, msg,sgn_cont_size);
    memcpy(signature, &msg[sgn_cont_size], sgn_size);

    bool check = verifySignature(signature_content, sgn_cont_size, pub_key, signature, sgn_size);
    if(!check){free(signature_content); free(signature); return false;}

    //Take client nonce
    if(nullptr == (nonce_peer = (unsigned char*)malloc(NONCESIZE))){free(signature); free(signature_content); return false;}
    memcpy(nonce_peer, &signature_content[MSGCODESIZE + USERNAME_SIZE_MAX], NONCESIZE);

    //TIME CHECK
    using namespace std::chrono;
    auto now = time_point_cast<milliseconds>(system_clock::now());
    using sys_milliseconds = decltype(now);
    uint64_t messageTimestamp;
    memcpy(&messageTimestamp, &msg[MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE], TIMESTAMPSIZE);
    sys_milliseconds dt{milliseconds{messageTimestamp}};
    duration<double> time_span = duration_cast<duration<double>>(dt - now);
    uint64_t time_span_abs = (time_span >= time_span.zero() ? time_span : -time_span).count();
    if( time_span_abs*1000 > TIMEWINDOW){
        cerr<<"Timestamp out of acceptance window."<<endl;
        return false;
    }


    free(signature);
    free(signature_content);
    return true;

}

//************************** HELLO RESPONSE MESSAGE - CREATION AND CHECKING METHODS*****


/**
 * This methods create a message of the type
 *
 *          HELLORESPONSE, ID, nonceID, nonceIDpeer, Yid, Sid(H(HELLORESPONSE, ID, nonceID, nonceIDpeer, Yid)), Certid(...)
 *
 *
 *
 * @param name, string which contains the ID of maximum lenght USERNAME_SIZE_MAX
 * @param cert
 * @param privkey, private key of ID
 * @param dh_key, DH keys of ID that will be used
 * @param len, lenght of the message
 * @return pointer to the allocated message
 */

unsigned char * SecureConnectionServlet::createHelloResponse(unsigned int header, string name, X509* cert, EVP_PKEY* privkey, unsigned char*& my_nonce, unsigned char* noncepeer, EVP_PKEY* dh_key, size_t& len) {

    //HEADER
    unsigned char* head = new unsigned char ;
    *head = (unsigned char)header;

    //ID
    char* ID = new char[USERNAME_SIZE_MAX];
    strcpy(ID, name.c_str());

    //NONCE
    if(nullptr == (my_nonce = createRandomValue(NONCESIZE))) return nullptr;

    //DH KEYS
    unsigned char* dhpubKey;size_t dhpubKeylen = 0;
    if(nullptr == ( dhpubKey = serializeKeys(dh_key, dhpubKeylen))) return nullptr;

    unsigned int sign_cont_len = MSGCODESIZE + USERNAME_SIZE_MAX + 2*NONCESIZE + dhpubKeylen;
    unsigned char* sign_cont = (unsigned char*)malloc(sign_cont_len);
    if(!sign_cont){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(sign_cont, head, MSGCODESIZE);
    memcpy(&sign_cont[MSGCODESIZE], ID, USERNAME_SIZE_MAX);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX], my_nonce, NONCESIZE);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE], noncepeer, NONCESIZE);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX + 2*NONCESIZE], dhpubKey, dhpubKeylen);

    size_t signatureLen = 0;
    unsigned char* signature;
    if(nullptr == ( signature = signObject(sign_cont, sign_cont_len, privkey, signatureLen))) return nullptr;
    len = sign_cont_len + signatureLen;


    unsigned char* certificate; size_t cert_len = 0;
    if(cert != nullptr){
        if(nullptr == (certificate = serializeCert(cert, cert_len))) return nullptr;
        len += cert_len;
    }

    unsigned char* msg = (unsigned char*)malloc(len);
    if(!msg){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(msg, sign_cont, sign_cont_len);
    memcpy(&msg[sign_cont_len], signature, signatureLen);
    if(cert != nullptr){
        memcpy(&msg[sign_cont_len + signatureLen], certificate, cert_len);
        OPENSSL_free(certificate);
    }

    delete head;
    delete[] ID;
    free(dhpubKey);
    free(sign_cont);
    free(signature);

    return msg;

}
/**
 * THis methods check the validity of the message made by createHelloResponse(...)
 *
 *                  HELLORESPONSE, ID, nonceID, nonceIDpeer, Yid, Sid(H(HELLORESPONSE, ID, nonceID, nonceIDpeer, Yid)), Certid(...)
 *
 *  Checks the Header, Extract the Certificate, Validate the Certificate, Extract the publicKey from the Certificate,
 *  Verify the signature with that public key, Verify that the nonce created int the previous message is the same,
 *  Save the DH Public key sent
 *
 * @param msg
 * @param len
 * @param store
 * @param dh_key
 * @return
 */

bool SecureConnectionServlet::checkHelloResponse(unsigned char *msg, size_t len, X509_STORE* store, EVP_PKEY* peer_pub_key, EVP_PKEY*& dh_peer_key, unsigned char* nonce, unsigned char *& nonceS){

    if(store == nullptr and peer_pub_key == nullptr){
        cerr<<"Error: missing parameters"<<endl;
        return false;
    }
    unsigned char* signature_content; size_t sgn_cont_size = len - SIGN_SIZE;
    if(store and peer_pub_key == nullptr){ sgn_cont_size -= CERT_SIZE ;}
    if(nullptr == ( signature_content = (unsigned char*)malloc(sgn_cont_size))) return false;

    unsigned char* signature; size_t sgn_size = SIGN_SIZE;
    if(nullptr == ( signature = (unsigned char* )malloc(sgn_size))) return false;

    unsigned char* certificate; size_t cert_size = CERT_SIZE;
    if(store and peer_pub_key == nullptr) {
        if (nullptr == (certificate = (unsigned char *) malloc(cert_size))) return false;
    }

    memcpy(signature_content, msg,sgn_cont_size);
    memcpy(signature, &msg[sgn_cont_size], sgn_size);
    if(store and peer_pub_key == nullptr) {
        memcpy(certificate, &msg[sgn_cont_size + sgn_size], CERT_SIZE);
        //Extract and validate the certificate
        X509* cert = deserializeCert(certificate, CERT_SIZE);
        if(!cert){free(signature_content); free(signature); free(certificate);return false;}
        bool check = verifyCertificate(cert, store);
        if(!check) {free(signature_content); free(signature); free(certificate);return false;}
        //Extracte public key from the certificate
        peer_pub_key = extractPubKeyFromCertificate(cert);
        if(!peer_pub_key || !EVP_PKEY_get1_RSA(peer_pub_key)) {free(signature_content); free(signature); free(certificate);return false;}

        free(certificate);
    }

    //Verify the signature
    bool check = verifySignature(signature_content, sgn_cont_size, peer_pub_key, signature, sgn_size);
    if(!check) {free(signature_content); free(signature); free(certificate);return false;}
    //Save the nonce of server
    nonceS = (unsigned char*)malloc(NONCESIZE);
    if(!nonceS){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(nonceS, &signature_content[MSGCODESIZE + USERNAME_SIZE_MAX ], NONCESIZE);

    //Compare the nonce the we sent
    if( 0 != (memcmp(&signature_content[MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE], nonce, NONCESIZE))){
        cerr<<"User nonce doesn't match. Possible Replay attack"<<endl;
        return false;
    }

    free(signature);
    free(signature_content);


    size_t dh_key_len = sgn_cont_size - USERNAME_SIZE_MAX - 2*NONCESIZE - MSGCODESIZE;
    dh_peer_key = deserializeKeys(&msg[USERNAME_SIZE_MAX + MSGCODESIZE + 2 * NONCESIZE], dh_key_len);
    if(dh_peer_key == nullptr || !EVP_PKEY_get1_EC_KEY(dh_peer_key)){cerr<<"Error deserializing DH keys"<<endl;return false;}

    return true;
}

//************************** HELLO ACCEPTANCE MESSAGE - CREATION AND CHECKING METHODS*****

/**
 * This method create a message of the form:
 *
 *              HELLOACCEPT, ID, noncePeer, Yid, Sid(H(HELLOACCEPT, ID, noncePeer, Yid))
 *
 *
 *42
* @param name
 * @param prvKey, private key to sign the message
 * @param dh_pub_key, DH public key that need to be sent
 * @param noncePeer, nonce of the peer previously received
 * @param len
 * @return
 */
unsigned char * SecureConnectionServlet::createHelloAcceptance(unsigned int header, string name, EVP_PKEY* prvKey, EVP_PKEY* dh_pub_key, unsigned char* noncePeer, size_t& len) {


    //HEADER
    char* head = (char*)calloc(1,sizeof(char));
    *head = ((char)header);


    //ID
    char* ID = (char*)malloc(USERNAME_SIZE_MAX);
    if(!ID){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memset(ID,0, USERNAME_SIZE_MAX);
    strcpy(ID, name.c_str());

    unsigned char* dhpubKey;size_t dhpubKeylen = 0;
    if(nullptr == ( dhpubKey = serializeKeys(dh_pub_key, dhpubKeylen))) return nullptr;

    //BIO_dump_fp(stdout, (const char*)dhpubKey, dhpubKeylen);

    unsigned int sign_cont_len = MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE + dhpubKeylen;
    unsigned char* sign_cont = (unsigned char*)malloc(sign_cont_len);
    if(!sign_cont){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(sign_cont, head, MSGCODESIZE);
    memcpy(&sign_cont[MSGCODESIZE], ID, USERNAME_SIZE_MAX);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX], noncePeer, NONCESIZE);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE], dhpubKey, dhpubKeylen);


    unsigned char* signature = nullptr; size_t signatureLen = 0;
    if(nullptr == ( signature = signObject(sign_cont,sign_cont_len,  prvKey, signatureLen))) return nullptr;

    unsigned char* msg = new unsigned char[(sign_cont_len + signatureLen)*sizeof(uint8_t)];

    // char* msg = (unsigned char*)malloc((sign_cont_len + signatureLen)*sizeof(uint8_t) );
    memcpy(msg, sign_cont, sign_cont_len);
    memcpy(&msg[sign_cont_len], signature, signatureLen);

    len = sign_cont_len + signatureLen;
    free(head);
    free(ID);
    free(sign_cont);
    free(signature);
    free(dhpubKey);

    return msg;

}
bool SecureConnectionServlet::checkHelloAcceptance(unsigned char *msg, size_t len, EVP_PKEY *pub_key,EVP_PKEY *&dh_peer_pub_key, unsigned char *nonce) {

    //BIO_dump_fp(stdout, (const char*)msg, len);
    //CHECK HEADER

    //Allocate space for the signature content HEADER, ID,
    unsigned char* signature_content; size_t sgn_cont_size = len - SIGN_SIZE;
    if(nullptr == ( signature_content = (unsigned char*)malloc(sgn_cont_size))) return false;

    unsigned char* signature; size_t sgn_size = SIGN_SIZE;
    if(nullptr == ( signature = (unsigned char* )malloc(sgn_size))) return false;


    memcpy(signature_content, msg,sgn_cont_size);
    memcpy(signature, &msg[sgn_cont_size], sgn_size);

    //Verify the signature
    bool check = verifySignature(signature_content, sgn_cont_size, pub_key, signature, sgn_size);
    if(!check) return false;

    if( 0 != (memcmp(&signature_content[MSGCODESIZE + USERNAME_SIZE_MAX], nonce, NONCESIZE))){
        cerr<<"User nonce doesn't match. Possible Replay attack"<<endl;
        return false;
    }
    size_t dh_key_len = sgn_cont_size - USERNAME_SIZE_MAX - NONCESIZE - MSGCODESIZE;
    unsigned char* keybuff = (unsigned char*)malloc(dh_key_len);
    if(!keybuff){cout<<"[ERROR] MEM ALLOC."<<endl; exit(1);}
    memcpy(keybuff,&signature_content[USERNAME_SIZE_MAX + MSGCODESIZE + NONCESIZE], dh_key_len );
    //BIO_dump_fp(stdout, (const char*)keybuff, dh_key_len);
    free(signature);
    free(signature_content);

    dh_peer_pub_key = deserializeKeys(keybuff, dh_key_len);
    if(dh_peer_pub_key == nullptr) return false;
    free(keybuff);

    return true;
}

/************************************************************************************************************************
 *
 *                                   UTILITY METHODS
 *
 * **********************************************************************************************************************
 */



EVP_PKEY* SecureConnectionServlet::generateNewDHKeys() {

    EVP_PKEY* newDHKeys = NULL;
    EVP_PKEY_CTX* ctx;
    if(!(ctx = EVP_PKEY_CTX_new(this->dh_params, NULL))){cerr<<"Error in DH key generation"<<endl;return nullptr;}
    /* Generate a new key */
    if(1 != EVP_PKEY_keygen_init(ctx)) {ERR_print_errors_fp(stderr);cerr<<"Error in DH key generation"<<endl;return nullptr;}
    if(1 != EVP_PKEY_keygen(ctx, &newDHKeys)) {ERR_print_errors_fp(stderr);cerr<<"Error in DH key generation"<<endl;return nullptr;}
    EVP_PKEY_CTX_free(ctx);
    return newDHKeys;
}

unsigned char * SecureConnectionServlet::serializeKeys(EVP_PKEY *keys, size_t& len) {

    //From key to char buffer
    BIO* mbio = BIO_new(BIO_s_mem());
    int ret = PEM_write_bio_PUBKEY(mbio, keys);//if contains also private key extract only public one
    if(!ret){
        //BIO_free(mbio);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    unsigned char* tmp = NULL;
    size_t dh_key_buff_len = BIO_get_mem_data(mbio, &tmp);
    if(dh_key_buff_len <= 0){
        //BIO_free(mbio);
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    //cout<<BIO_CLOSE<<endl;
    unsigned char* dh_key_buff = (unsigned char*)malloc(dh_key_buff_len);
    if(!dh_key_buff){cerr<<"Error in malloc"<<endl;return nullptr;}
    memcpy(dh_key_buff, tmp, dh_key_buff_len);
    BIO_free(mbio);
    len = dh_key_buff_len;
    return dh_key_buff;

}
EVP_PKEY * SecureConnectionServlet::deserializeKeys(unsigned char* key, size_t len) {
    BIO* mbio = BIO_new(BIO_s_mem());
    BIO_write(mbio, key, len);
    EVP_PKEY* pubKey = PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
    if(!pubKey){
        cerr<<"Error Deserializing DH keys"<<endl;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    BIO_free(mbio);
    return pubKey;
}


unsigned char* SecureConnectionServlet::signObject(unsigned char* sign_cont , size_t sign_cont_len, EVP_PKEY* privkey, size_t& len){

    if(!EVP_PKEY_get1_RSA(privkey)){
        cout<<"Private key corrupted."<<endl;
    }
    unsigned char* signature = (unsigned char*)malloc(EVP_PKEY_size(privkey)*sizeof(uint8_t));
    if(!signature){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    memset(signature, 0, EVP_PKEY_size(privkey));

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int ret = EVP_SignInit(md_ctx, EVP_sha256());
    if(ret<= 0){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Creation"<<endl;
        free(signature);
        return nullptr;
    }
    ret = EVP_SignUpdate(md_ctx, sign_cont, sign_cont_len);
    if(ret<= 0){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Creation"<<endl;
        free(signature);
        return nullptr;
    }
    unsigned int sgn_size = 0;
    ret = EVP_SignFinal(md_ctx, signature, &sgn_size, privkey);
    if(ret<= 0){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Creation"<<endl;
        free(signature);
        return nullptr;
    }
    len = sgn_size;
    EVP_MD_CTX_free(md_ctx);
    return signature;

}

bool SecureConnectionServlet::verifySignature(unsigned char* signature_content, size_t sign_cont_len,EVP_PKEY* pubkey , unsigned char* signature, size_t signature_len){

    //Check SIgnature
    const EVP_MD* md = EVP_sha256();
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    int ret =EVP_VerifyInit(md_ctx, md);
    if(ret != 1){

        EVP_MD_CTX_free(md_ctx);
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Verification: The message has been modified.(init)"<<endl;
        return false;
    }
    ret = EVP_VerifyUpdate(md_ctx, signature_content, sign_cont_len);
    if(ret != 1){

        EVP_MD_CTX_free(md_ctx);
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Verification: The message has been modified.(Update)"<<endl;
        return false;
    }
    ret = EVP_VerifyFinal(md_ctx, signature, signature_len, pubkey);
    if(ret != 1){
        EVP_MD_CTX_free(md_ctx);
        ERR_print_errors_fp(stderr);
        cerr<<"Error Signature Verification: The message has been modified.(Final)"<<endl;
        return false;
    }

    EVP_MD_CTX_free(md_ctx);
    return true;

}

unsigned char *SecureConnectionServlet::serializeCert(X509 *cert, size_t &len) {

    unsigned char* cert_buf = nullptr;
    int cert_size = i2d_X509(cert, &cert_buf);
    if( cert_size < 0){
        cerr<<"Error serializing certificate"<<endl;
        return nullptr;
    }
    len = cert_size;
    return cert_buf;
}
X509 * SecureConnectionServlet::deserializeCert(unsigned char* cert_buf, size_t cert_size) {
    X509 * cert = d2i_X509(NULL, (const unsigned char**)&cert_buf, cert_size);
    if(!cert){
        cerr<<"Error deserializing certificate"<<endl;
        return nullptr;
    }
    return cert;
}
bool SecureConnectionServlet::verifyCertificate(X509 *cert, X509_STORE *store) {

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    int ret = X509_verify_cert(ctx);
    if(ret != 1){
        ERR_print_errors_fp(stderr);
        cerr<<" Certificate is not valid."<<endl;
        return false;
    }
    X509_STORE_CTX_free(ctx);
    return true;
}

EVP_PKEY *SecureConnectionServlet::extractPubKeyFromCertificate(X509 *cert) {


    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    if(!pubKey){
        ERR_print_errors_fp(stderr);
        cerr<<"ERROR EXTRACTING PUBLIC KEY"<<endl;
        cerr<<"Closing..."<<endl;
        return nullptr;
    }
    return pubKey;
}

unsigned char *SecureConnectionServlet::deriveSecretDH(EVP_PKEY *privKey, EVP_PKEY *peer_key, size_t& secret_len) {

    // DERIVE KEY SESSION FROM THE TWO DH KEYS
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, NULL);
    int ret = EVP_PKEY_derive_init(ctx);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    ret = EVP_PKEY_derive_set_peer(ctx, peer_key);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    unsigned char* secret; size_t len;
    ret = EVP_PKEY_derive(ctx, NULL, &len);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    secret = (unsigned char*)malloc(len);
    if(!secret){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    ret = EVP_PKEY_derive(ctx, secret, &len);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);


    // HASH IT TO INCREASE ENTROPY
    unsigned int outlen;
    unsigned char* hashed_secret = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if(!hashed_secret){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    EVP_MD_CTX* ctx_md = EVP_MD_CTX_new();
    ret = EVP_DigestInit(ctx_md, EVP_sha256());
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    ret = EVP_DigestUpdate(ctx_md, secret, len);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    ret = EVP_DigestFinal(ctx_md, hashed_secret, &outlen);
    if( ret < 1){
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    EVP_MD_CTX_free(ctx_md);
    secret_len = outlen;

    free(secret);

    unsigned char* key = (unsigned char*)malloc(KEY_SIZE);
    if(!key){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    memcpy(key, hashed_secret, KEY_SIZE);
    free(hashed_secret);
    return key;

}


unsigned char *SecureConnectionServlet::gcmEncrypt(unsigned char *pt, size_t pt_len,
                                                   size_t& ct_len,
                                                   unsigned char* key,
                                                   unsigned char* aad, size_t aad_len,
                                                   unsigned char* iv,
                                                   unsigned char*& tag) {
    //BIO_dump_fp(stdout,(const char*) key, KEY_SIZE);

    EVP_CIPHER_CTX* ctx;
    int ciphertext_len;
    int len;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cerr<<"Error creating context"<<endl;
        return nullptr;
    }
    if( 1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        cerr<<"Error Init Encryption"<<endl;
        return nullptr;
    }
    unsigned char* ct = (unsigned char*)malloc(pt_len);
    if(!ct){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    if( 1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Update Encryption"<<endl;
        return nullptr;
    }

    if( 1 != EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Update Encryption"<<endl;
        return nullptr;
    }

    ciphertext_len = len;
    if(1 != EVP_EncryptFinal(ctx, ct + len, &len)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Finalize Encryption"<<endl;
        return nullptr;

    }
    ciphertext_len +=len;
    tag = (unsigned char*)malloc(GCM_TAG_LEN);
    if(!tag){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, tag)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error getting tag Encryption"<<endl;
        return nullptr;
    }
    ct_len = ciphertext_len;
    EVP_CIPHER_CTX_free(ctx);

    return ct;
}

unsigned char *SecureConnectionServlet::gcmDecrypt(unsigned char *ct, size_t ct_len, size_t &pt_len, unsigned char *key,
                                                   unsigned char *aad, size_t aad_len, unsigned char *iv,
                                                   unsigned char *tag) {

    EVP_CIPHER_CTX* ctx;
    int len;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cerr<<"Error creating context"<<endl;
        return nullptr;
    }
    if( 1 != EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        cerr<<"Error Init Encryption"<<endl;
        return nullptr;
    }
    unsigned char* pt = (unsigned char*)malloc(ct_len);
    if(!pt){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    memset(pt, 0, ct_len);
    if( 1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        cerr<<"Error Update Encryption"<<endl;
        return nullptr;
    }

    if( 1 != EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len)){
        cerr<<"Error Update Encryption"<<endl;
        return nullptr;
    }
    pt_len = len;

    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN, tag)){
        cerr<<"Error getting tag Decryption"<<endl;
        return nullptr;
    }
    int ret = EVP_DecryptFinal(ctx, pt + len, &len);
    EVP_CIPHER_CTX_cleanup(ctx);
    if( ret > 0){
        pt_len += len;
    }else{
        cout<<"Error decrypting final"<<endl;
        return nullptr;
    }


    return pt;

}



unsigned char * SecureConnectionServlet::gmacEncrypt(unsigned char *key, unsigned char *aad, size_t aad_len, unsigned char *iv) {


    EVP_CIPHER_CTX* ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cerr<<"Error creating context"<<endl;
        return nullptr;
    }
    if( 1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        cerr<<"Error Init Encryption"<<endl;
        return nullptr;
    }
    int ct_len;//unused
    if( 1 != EVP_EncryptUpdate(ctx, NULL, reinterpret_cast<int *>(&ct_len), aad, aad_len)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Update Encryption"<<endl;
        return nullptr;
    }

    if(1 != EVP_EncryptFinal(ctx, NULL, reinterpret_cast<int *>(&ct_len))){
        ERR_print_errors_fp(stderr);
        cerr<<"Error Finalize Encryption"<<endl;
        return nullptr;

    }
    unsigned char*tag = (unsigned char*)malloc(GCM_TAG_LEN);
    if(!tag){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LEN, tag)){
        ERR_print_errors_fp(stderr);
        cerr<<"Error getting tag Encryption"<<endl;
        return nullptr;
    }
    EVP_CIPHER_CTX_free(ctx);

    return tag;

}

bool SecureConnectionServlet::gmacDecrypt(unsigned char *key, unsigned char *aad, size_t aad_len, unsigned char *iv,
                                          unsigned char *tag) {


    EVP_CIPHER_CTX* ctx;
    if(!(ctx = EVP_CIPHER_CTX_new())){
        cerr<<"Error creating context"<<endl;
        return false;
    }

    if( 1 != EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)){
        cerr<<"Error Init Encryption"<<endl;
        return false;
    }
   int pt_len = 0; int ct_len = 0;
    if( 1 != EVP_DecryptUpdate(ctx, NULL, reinterpret_cast<int *>(&ct_len), aad, aad_len)){
        cerr<<"Error Update Encryption"<<endl;
        return false;
    }

    if( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LEN, tag)){
        cerr<<"Error getting tag Decryption"<<endl;
        return false;
    }
    int ret = EVP_DecryptFinal(ctx, NULL, reinterpret_cast<int *>(&pt_len));
    EVP_CIPHER_CTX_cleanup(ctx);
    if( ret <= 0){
        return false;
    }


    return true;
}

unsigned char * SecureConnectionServlet::createAuthenticatedMsg(unsigned int header, string name, unsigned char *key,
                                                     unsigned char *&iv, unsigned char* payload, size_t payload_len, size_t &len, unsigned int GCM_GMAC) {

    //HEADER
    char* head = new char ;
    *head = header;

    //ID
    char* ID = (char*)malloc(USERNAME_SIZE_MAX);
    if(!ID){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    memset(ID,0, USERNAME_SIZE_MAX);
    strcpy(ID, name.c_str());

    //NONCE
    bool new_iv = false;
    if(iv == nullptr){
        new_iv = true;
        if(nullptr == (iv = createRandomValue(IV_LEN))) {cout<<"Error creating random value."<<endl; delete head; free(ID); return nullptr;}
    }else{
        (*iv)++;
    }

    // AAD = HEADER + ID
    unsigned char* aad = (unsigned char*)malloc(MSGCODESIZE + USERNAME_SIZE_MAX);
    if(!aad){
        cerr<<"Malloc Error"<<endl;
        return nullptr;
    }
    memcpy(aad, head, MSGCODESIZE);
    memcpy(&aad[MSGCODESIZE], ID, USERNAME_SIZE_MAX);

    //GMAC
    unsigned char* tag; unsigned char* ct; size_t ct_len = 0;
    if(GCM_GMAC == GMAC){
        tag = gmacEncrypt(key, aad, MSGCODESIZE + USERNAME_SIZE_MAX, iv);
        if(!tag){cout<<"Error creating GMAC"<<endl; return nullptr;}
    }else if(GCM_GMAC == GCM){
        ct =  gcmEncrypt(payload, payload_len, ct_len, key, aad, MSGCODESIZE + USERNAME_SIZE_MAX,iv, tag);
        if(!ct){cerr<<"Error encrypting GCM."<<endl;}
    }else{
        cout<<"Error inserting type of msg"<<endl;
        delete head; free(ID); free(aad);
        if(new_iv){
            iv = nullptr;
        }else{
            *(iv)--;
        }
    }

    len = MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN + GCM_TAG_LEN;
    if(GCM_GMAC == GCM){ len += ct_len;}
    unsigned char* msg = (unsigned char*)malloc(len);
    if(!msg){cout<<"Error malloc"<<endl; delete head; free(ID); free(aad);
        if(new_iv){
            iv = nullptr;
        }else{
            (*iv)--;
        }
        return nullptr;
    }
    memcpy(msg,head, MSGCODESIZE );
    memcpy(&msg[MSGCODESIZE],ID, USERNAME_SIZE_MAX );
    memcpy(&msg[MSGCODESIZE + USERNAME_SIZE_MAX ],iv, IV_LEN );
    if(GCM_GMAC == GMAC){
        memcpy(&msg[MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN],tag, GCM_TAG_LEN );
    }else if(GCM_GMAC == GCM){
        memcpy(&msg[MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN], ct, ct_len);
        memcpy(&msg[MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN + ct_len],tag, GCM_TAG_LEN );
        free(ct);

    }

    delete head; free(ID); free(aad); free(tag);
    return msg;

}

bool SecureConnectionServlet::checkAuthenticatedMsg(unsigned char *msg, size_t msg_len, unsigned char *key,
                                                    unsigned char *&iv_peer, unsigned char*& pt, size_t& pt_len, unsigned int GCM_GMAC) {

    //Deserialize data
    unsigned char* aad = (unsigned char*)malloc(MSGCODESIZE + USERNAME_SIZE_MAX);
    if(!aad){cout<<"Malloc error."<<endl; exit(1);}
    memcpy(aad, msg, MSGCODESIZE + USERNAME_SIZE_MAX);

    bool new_iv = false;
    unsigned char* iv = (unsigned char*)malloc(IV_LEN);
    if(!iv){cout<<"Malloc error."<<endl; exit(1);}
    memcpy(iv, &msg[MSGCODESIZE + USERNAME_SIZE_MAX], IV_LEN);
    if(iv_peer == nullptr){
        new_iv = true;
        iv_peer = iv;
    }else{
        (*iv_peer)++;
        if(0 != memcmp(iv, iv_peer, IV_LEN)){
            cout<<"Error IV mismatch, possible replay attack"<<endl;
            return false;
        }
    }

    unsigned char* tag = (unsigned char*)malloc(GCM_TAG_LEN);
    if(!tag){cout<<"Malloc error."<<endl; exit(1);}
    memcpy(tag, &msg[msg_len - GCM_TAG_LEN], GCM_TAG_LEN);

    bool check = false;
    if(GCM_GMAC == GMAC){
        check = gmacDecrypt(key, aad, MSGCODESIZE + USERNAME_SIZE_MAX, iv, tag);
        if(!check){
            cout<<"Error Decrypting"<<endl;
        }
    }else if(GCM_GMAC == GCM){
        size_t ct_len = msg_len - (MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN + GCM_TAG_LEN);
        pt = gcmDecrypt(&msg[MSGCODESIZE + USERNAME_SIZE_MAX + IV_LEN],ct_len,  pt_len, key, aad, MSGCODESIZE + USERNAME_SIZE_MAX, iv_peer,  tag);
        if(!pt){
            cout<<"Error Decrypting GCM"<<endl;
            return false;
        }
        check = true;

    }else{
        cout<<"Error king of data type encryption"<<endl;
        return false;

    }
    free(aad);
    free(tag);
    if(!new_iv){ free(iv);}

    return check;

}

unsigned char *
SecureConnectionServlet::createHelloRefuse(unsigned int header, string name, unsigned char* peer_nonce, X509 *cert, EVP_PKEY *prvkey,
                                           size_t &len) {

    //HEADER
    char* head = (char*)malloc(MSGCODESIZE*sizeof(uint8_t));
    if(!head){cout<<"Malloc Error."<<endl; exit(1);}
    //unsigned char* header = new unsigned char ;
    *head = (char)header;

    //ID
    char* ID = (char*)malloc(USERNAME_SIZE_MAX*sizeof(uint8_t));
    if(!ID){cout<<"Malloc Error."<<endl; exit(1);}
    memset(ID,0, USERNAME_SIZE_MAX);
    strcpy(ID, name.c_str());

    unsigned int sign_cont_len = MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE;
    unsigned char* sign_cont = (unsigned char*)malloc(sign_cont_len*sizeof(uint8_t));
    if(!sign_cont){cout<<"Malloc Error."<<endl; exit(1);}
    memcpy(sign_cont, head, MSGCODESIZE);
    memcpy(&sign_cont[MSGCODESIZE], ID, USERNAME_SIZE_MAX);
    memcpy(&sign_cont[MSGCODESIZE + USERNAME_SIZE_MAX], peer_nonce, NONCESIZE);

    size_t signatureLen = 0;
    unsigned char* signature;
    if(nullptr == ( signature = signObject(sign_cont,sign_cont_len, prvkey, signatureLen))){ free(head); free(ID); free(sign_cont);return nullptr;}

    //IF CERT != NULLPTR IS AN HELLOREFUSE FROM SERVER OTHERWISE IS FROM THE CLIENT
    len = sign_cont_len + signatureLen;
    unsigned char* certificate; size_t cert_len = 0;
    if(cert != nullptr){
        if(nullptr == (certificate = serializeCert(cert, cert_len))) return nullptr;
        len += cert_len;
    }


    unsigned char* msg = (unsigned char*)malloc(sign_cont_len + signatureLen);
    if(!msg){cout<<"Malloc Error."<<endl; exit(1);}
    memcpy(msg, sign_cont, sign_cont_len);
    memcpy(&msg[sign_cont_len], signature, signatureLen);
    if(cert != nullptr){
        memcpy(&msg[sign_cont_len + signatureLen], certificate, cert_len);
        OPENSSL_free(certificate);
    }

    free(head);
    free(ID);
    free(sign_cont);
    free(signature);

    return msg;
}

bool SecureConnectionServlet::checkHelloRefuse(unsigned char *msg, size_t len, X509_STORE* store, EVP_PKEY* peer_pub_key, unsigned char* my_nonce) {


    if(store and peer_pub_key == nullptr) {//extract the public key
        unsigned char* certificate; size_t cert_size = CERT_SIZE;
        if (nullptr == (certificate = (unsigned char *) malloc(cert_size))) return false;

        memcpy(certificate, &msg[len - CERT_SIZE], CERT_SIZE);
        //Extract and validate the certificate
        X509 *cert = deserializeCert(certificate, CERT_SIZE);
        if (!cert) {
            free(certificate);
            return false;
        }
        bool check = verifyCertificate(cert, store);
        if (!check) {
            free(certificate);
            return false;
        }
        //Extracte public key from the certificate
        peer_pub_key = extractPubKeyFromCertificate(cert);
        if (!peer_pub_key || !EVP_PKEY_get1_RSA(peer_pub_key)) {
            free(certificate);
            return false;
        }
        free(certificate);
    }


    //Extract the content
    unsigned char* signature_content; size_t sgn_cont_size = MSGCODESIZE + USERNAME_SIZE_MAX + NONCESIZE;
    if(nullptr == ( signature_content = (unsigned char*)malloc(sgn_cont_size))) return false;
    memcpy(signature_content, msg,sgn_cont_size);
    //Verify the nonce
    if( 0 != (memcmp(&signature_content[MSGCODESIZE + USERNAME_SIZE_MAX], my_nonce, NONCESIZE))){
        cerr<<"User nonce doesn't match. Possible Replay attack"<<endl;
        free(signature_content);
        return false;
    }

    unsigned char* signature; size_t sgn_size = SIGN_SIZE;
    if(nullptr == ( signature = (unsigned char* )malloc(sgn_size))){free(signature_content); return false;}
    memcpy(signature, &msg[sgn_cont_size], sgn_size);
    //verify the signature
    bool check = verifySignature(signature_content, sgn_cont_size, peer_pub_key, signature, sgn_size);
    if(!check){free(signature_content); free(signature);return false;}

    free(signature);
    free(signature_content);

    return true;
}


