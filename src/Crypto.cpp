#include "Crypto.h"
#include<iostream>
using namespace std;
EVP_PKEY* Crypto::localKeypair;
FILE* pFile = NULL;

Crypto::Crypto() {
localKeypair = NULL;
remotePubKey = NULL;
genTestClientKey();
init();
}

Crypto::~Crypto() {
EVP_PKEY_free(remotePubKey);
EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
free(rsaEncryptCtx);
free(aesEncryptCtx);
free(rsaDecryptCtx);
free(aesDecryptCtx);
free(aesKey);
free(aesIV);
}

int Crypto::sign_alt(unsigned char *msg_s, unsigned int msg_s_length,  unsigned char *sig_s, unsigned int sig_len_s,EVP_MD_CTX *mdctx,char* key_file,char* cert_file)
{
		int ret = 0;
		int err;
		FILE *fp;
		EVP_PKEY *pkey;
		string s;
		//static char certfile[] = cert_file;
		//static char keyfile[] = key_file;


		unsigned char *msg = new unsigned char[msg_s_length];
		memcpy(msg,msg_s,msg_s_length);
		unsigned long int slen;


		/* Read private key */
			fp = fopen(key_file, "r");
			if (fp == NULL)
			exit(1);
			pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
			fclose(fp);
			if (pkey == NULL) {
			ERR_print_errors_fp(stderr);
			exit(1);
			}
			//printf("private key read");

		/* Create the Message Digest Context */


		/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
		 if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
			 printf("error");

		 /* Call update with the message */
		 if(1 != EVP_DigestSignUpdate(mdctx, msg, msg_s_length))
			 printf("error");

		 /* Finalise the DigestSign operation */
		 /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
		  * signature. Length is returned in slen */
		 if(1 != EVP_DigestSignFinal(mdctx, NULL, &slen))
			 printf("error");
		 /* Allocate memory for the signature based on size in slen */
		 unsigned char *sig = new unsigned char[slen];
		 sig_len_s = slen;
		 //cout<<endl<<"size of signature:"<<slen<<endl;
		 /* Obtain the signature */
		 if(1 != EVP_DigestSignFinal(mdctx, sig, &slen))
			 printf("error");
		 memcpy(sig_s,sig,slen);

		 /* Success */
		 ret = 1;
		 //printf("success");



		 /* Clean up */
		 //if(*sig && !ret) OPENSSL_free(*sig);
		// if(mdctx) EVP_MD_CTX_destroy(mdctx);
		 return (0);

}

int Crypto::verify_alt(EVP_MD_CTX *mdctx,unsigned char *msg_s, unsigned int msg_s_length, unsigned char *sig_s, unsigned int sig_len_s,char *key_file,char *cert_file)
{
	int ret = 0;
	int err;
	FILE *fp;
	X509 *x509;
	EVP_PKEY *pkey;
	//static char certfile[] = cert_file;
	//static char keyfile[] = key_file;

	fp = fopen(cert_file, "r");
		if (fp == NULL)
		exit(1);
		x509 = PEM_read_X509(fp, NULL, NULL, NULL);
		fclose(fp);
		if (x509 == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
		}
		/* Get public key - eay */
		pkey = X509_get_pubkey(x509);
		if (pkey == NULL) {
		ERR_print_errors_fp(stderr);
		exit(1);
		}



	/* Initialize `key` with a public key */
	if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey))
		cout<<"error";

	/* Initialize `key` with a public key */
	if(1 != EVP_DigestVerifyUpdate(mdctx, msg_s, msg_s_length))
		cout<<"error";

	if(1 == EVP_DigestVerifyFinal(mdctx, sig_s, sig_len_s))
	{
		cout<<"Successfully verified..";
		return 0;
		/* Success */
	}
	else
	{
		cout<<"failure in verification";
		return -1;
	    /* Failure */
	}


}

int Crypto::aesEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg) {
size_t blockLen = 0;
size_t encMsgLen = 0;
*encMsg = (unsigned char*)malloc(msgLen + AES_BLOCK_SIZE);
if(encMsg == NULL) return FAILURE;
if(!EVP_EncryptInit_ex(aesEncryptCtx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)) {
return FAILURE;
}
if(!EVP_EncryptUpdate(aesEncryptCtx, *encMsg, (int*)&blockLen, (unsigned char*)msg, msgLen)) {
return FAILURE;
}
encMsgLen += blockLen;
if(!EVP_EncryptFinal_ex(aesEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
return FAILURE;
}
EVP_CIPHER_CTX_cleanup(aesEncryptCtx);
return encMsgLen + blockLen;
}

int Crypto::aesDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char **decMsg) {
size_t decLen = 0;
size_t blockLen = 0;
*decMsg = (unsigned char*)malloc(encMsgLen);
if(*decMsg == NULL) return FAILURE;
if(!EVP_DecryptInit_ex(aesDecryptCtx, EVP_aes_256_cbc(), NULL, aesKey, aesIV)) {
return FAILURE;
}
if(!EVP_DecryptUpdate(aesDecryptCtx, (unsigned char*)*decMsg, (int*)&blockLen, encMsg, (int)encMsgLen)) {
return FAILURE;
}
decLen += blockLen;
if(!EVP_DecryptFinal_ex(aesDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
return FAILURE;
}
decLen += blockLen;
EVP_CIPHER_CTX_cleanup(aesDecryptCtx);
return (int)decLen;
}


int Crypto::rsaEncrypt(const unsigned char *msg, size_t msgLen, unsigned char **encMsg, unsigned char **ek, size_t *ekl, unsigned char **iv, size_t *ivl) {
size_t encMsgLen = 0;
size_t blockLen = 0;
*ek = (unsigned char*)malloc(EVP_PKEY_size(remotePubKey));
*iv = (unsigned char*)malloc(EVP_MAX_IV_LENGTH);
if(*ek == NULL || *iv == NULL) return FAILURE;
*ivl = EVP_MAX_IV_LENGTH;
*encMsg = (unsigned char*)malloc(msgLen + EVP_MAX_IV_LENGTH);
if(encMsg == NULL) return FAILURE;
if(!EVP_SealInit(rsaEncryptCtx, EVP_aes_256_cbc(), ek, (int*)ekl, *iv, &remotePubKey, 1)) {
return FAILURE;
}
if(!EVP_SealUpdate(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen, (const unsigned char*)msg, (int)msgLen)) {
return FAILURE;
}
encMsgLen += blockLen;
if(!EVP_SealFinal(rsaEncryptCtx, *encMsg + encMsgLen, (int*)&blockLen)) {
return FAILURE;
}
encMsgLen += blockLen;
EVP_CIPHER_CTX_cleanup(rsaEncryptCtx);
printf("\n Encryption successfull \n");
return (int)encMsgLen;
}

int Crypto::rsaDecrypt(unsigned char *encMsg, size_t encMsgLen, unsigned char *ek, size_t ekl, unsigned char *iv, size_t ivl, unsigned char **decMsg) {
size_t decLen = 0;
size_t blockLen = 0;
EVP_PKEY *key;
*decMsg = (unsigned char*)malloc(encMsgLen + ivl);
if(decMsg == NULL) return FAILURE;

key = remotePubKey;

if(!EVP_OpenInit(rsaDecryptCtx, EVP_aes_256_cbc(), ek, ekl, iv, key)) {
return FAILURE;
}
if(!EVP_OpenUpdate(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen, encMsg, (int)encMsgLen)) {
return FAILURE;
}
decLen += blockLen;
if(!EVP_OpenFinal(rsaDecryptCtx, (unsigned char*)*decMsg + decLen, (int*)&blockLen)) {
return FAILURE;
}
decLen += blockLen;
EVP_CIPHER_CTX_cleanup(rsaDecryptCtx);
return (int)decLen;
}

int Crypto::hash(unsigned char *encMsg,  size_t encMsgLen,unsigned char *encMsg2,  size_t encMsg2Len, unsigned char digest[], unsigned int md_len) {

	EVP_MD_CTX *mdctx;
	 const EVP_MD *md;
	 unsigned char *mess1 = encMsg;
	 unsigned char *mess2 = encMsg2;
	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 unsigned int i;
	 char arg[] = "SHA256";

	 OpenSSL_add_all_digests();

	 md = EVP_get_digestbyname(arg);

	 if(!md) {
	        printf("Unknown message digest %s\n", arg);
	        exit(1);
	 }

	 mdctx = EVP_MD_CTX_create();
	 EVP_DigestInit_ex(mdctx, md, NULL);
	 EVP_DigestUpdate(mdctx, mess1, encMsgLen);
	 EVP_DigestUpdate(mdctx, mess2, encMsg2Len);
	 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	 EVP_MD_CTX_destroy(mdctx);
	 memcpy(digest,md_value,32);

	 /* Call this once before exit. */
	 EVP_cleanup();

	 //exit(0);
}

int Crypto::hash(unsigned char *encMsg,  size_t encMsgLen, unsigned char digest[], unsigned int md_len) {

	EVP_MD_CTX *mdctx;
	 const EVP_MD *md;
	 unsigned char *mess1 = encMsg;
	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 unsigned int i;
	 char arg[] = "SHA256";

	 OpenSSL_add_all_digests();

	 md = EVP_get_digestbyname(arg);

	 if(!md) {
	        printf("Unknown message digest %s\n", arg);
	        exit(1);
	 }

	 mdctx = EVP_MD_CTX_create();
	 EVP_DigestInit_ex(mdctx, md, NULL);
	 EVP_DigestUpdate(mdctx, mess1, encMsgLen);
	 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	 EVP_MD_CTX_destroy(mdctx);
	 memcpy(digest,md_value,32);

	 /* Call this once before exit. */
	 EVP_cleanup();

	 return 1;
	 //exit(0);
}

int Crypto::hash(unsigned char *encMsg,  size_t encMsgLen,unsigned char *encMsg2,  size_t encMsg2Len,unsigned char *encMsg3,  size_t encMsg3Len, unsigned char digest[], unsigned int md_len) {

	 EVP_MD_CTX *mdctx;
	 const EVP_MD *md;
	 unsigned char *mess1 = encMsg;
	 unsigned char *mess2 = encMsg2;
	 unsigned char md_value[EVP_MAX_MD_SIZE];
	 unsigned int i;
	 char arg[] = "SHA256";

	 OpenSSL_add_all_digests();

	 md = EVP_get_digestbyname(arg);

	 if(!md) {
	        printf("Unknown message digest %s\n", arg);
	        exit(1);
	 }

	 mdctx = EVP_MD_CTX_create();
	 EVP_DigestInit_ex(mdctx, md, NULL);
	 EVP_DigestUpdate(mdctx, mess1, encMsgLen);
	 EVP_DigestUpdate(mdctx, mess2, encMsg2Len);
	 EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	 EVP_MD_CTX_destroy(mdctx);
	 memcpy(digest,md_value,32);

	 /* Call this once before exit. */
	 EVP_cleanup();

	 //exit(0);
}


int Crypto::hmac(unsigned char *encMsg,  size_t encMsgLen,unsigned char *key, int key_length, unsigned char *digest, unsigned int md_len)
{


	    // The data that we're going to hash using HMAC

		//char keys[] = "fhksjdfh";
	    // Using sha1 hash engine here.
	    // You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
	    if(!(digest = HMAC(EVP_sha256(), (unsigned char*)key,key_length,encMsg, encMsgLen, digest, &md_len)))
	    {
	    	printf("Hashing failed");
	    }

	    //md_len = 32;
	    //printf("HMAC Done");
	    // Be careful of the length of string with the choosen hash engine. SHA1 produces a 20-byte hash value which rendered as 40 characters.
	    // Change the length accordingly with your choosen hash engine
	    char mdString[32];
	    return 1;
}



int Crypto::writeKeyToFile(FILE *fd, int key) {
switch(key) {
case KEY_SERVER_PRI:
if(!PEM_write_PrivateKey(fd, localKeypair, NULL, NULL, 0, 0, NULL)) {
return FAILURE;
}
break;
case KEY_SERVER_PUB:
if(!PEM_write_PUBKEY(fd, localKeypair)) {
return FAILURE;
}
break;
case KEY_CLIENT_PUB:
if(!PEM_write_PUBKEY(fd, remotePubKey)) {
return FAILURE;
}
break;
case KEY_AES:
fwrite(aesKey, 1, AES_KEYLEN, fd);
break;
case KEY_AES_IV:
fwrite(aesIV, 1, AES_KEYLEN, fd);
break;
case KEY_CLIENT_PRI:
if(!PEM_write_PrivateKey(fd, remotePubKey, NULL, NULL, 0, 0, NULL)) {
return FAILURE;
}
break;
default:
return FAILURE;
}
return SUCCESS;
}

int Crypto::getRemotePubKey(unsigned char **pubKey) {
BIO *bio = BIO_new(BIO_s_mem());
PEM_write_bio_PUBKEY(bio, remotePubKey);
int pubKeyLen = BIO_pending(bio);
*pubKey = (unsigned char*)malloc(pubKeyLen);
if(pubKey == NULL) return FAILURE;
BIO_read(bio, *pubKey, pubKeyLen);
// Insert the NUL terminator
(*pubKey)[pubKeyLen-1] = '\0';
BIO_free_all(bio);
return pubKeyLen;
}

int Crypto::setRemotePubKey(unsigned char* pubKey, size_t pubKeyLen) {
//BIO *bio = BIO_new(BIO_f_base64());
BIO *bio = BIO_new(BIO_s_mem());
if(BIO_write(bio, pubKey, pubKeyLen) != (int)pubKeyLen) {
return FAILURE;
}
RSA *_pubKey = (RSA*)malloc(sizeof(RSA));
if(_pubKey == NULL) return FAILURE;
PEM_read_bio_PUBKEY(bio, &remotePubKey, NULL, NULL);
BIO_free_all(bio);
return SUCCESS;
}

int Crypto::getLocalPubKey(unsigned char** pubKey) {
BIO *bio = BIO_new(BIO_s_mem());
PEM_write_bio_PUBKEY(bio, localKeypair);
int pubKeyLen = BIO_pending(bio);
*pubKey = (unsigned char*)malloc(pubKeyLen);
if(pubKey == NULL) return FAILURE;
BIO_read(bio, *pubKey, pubKeyLen);
// Insert the NUL terminator
(*pubKey)[pubKeyLen-1] = '\0';
BIO_free_all(bio);
return pubKeyLen;
}

int Crypto::getLocalPriKey(unsigned char **priKey) {
BIO *bio = BIO_new(BIO_s_mem());
PEM_write_bio_PrivateKey(bio, localKeypair, NULL, NULL, 0, 0, NULL);
int priKeyLen = BIO_pending(bio);
*priKey = (unsigned char*)malloc(priKeyLen + 1);
if(priKey == NULL) return FAILURE;
BIO_read(bio, *priKey, priKeyLen);
// Insert the NUL terminator
(*priKey)[priKeyLen] = '\0';
BIO_free_all(bio);
return priKeyLen;
}
int Crypto::getAESKey(unsigned char **aesKey) {
*aesKey = this->aesKey;
return AES_KEYLEN/8;
}
int Crypto::setAESKey(unsigned char *aesKey, size_t aesKeyLen) {
// Ensure the new key is the proper size
if((int)aesKeyLen != AES_KEYLEN/8) {
return FAILURE;
}
memcpy(this->aesKey, aesKey, AES_KEYLEN/8);
return SUCCESS;
}
int Crypto::getAESIv(unsigned char **aesIV) {
*aesIV = this->aesIV;
return AES_KEYLEN/16;
}
int Crypto::setAESIv(unsigned char *aesIV, size_t aesIVLen) {
// Ensure the new IV is the proper size
if((int)aesIVLen != AES_KEYLEN/16) {
return FAILURE;
}
memcpy(this->aesIV, aesIV, AES_KEYLEN/16);
return SUCCESS;
}

int Crypto::init() {
// Initalize contexts
rsaEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
aesEncryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
rsaDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
aesDecryptCtx = (EVP_CIPHER_CTX*)malloc(sizeof(EVP_CIPHER_CTX));
// Always a good idea to check if malloc failed
if(rsaEncryptCtx == NULL || aesEncryptCtx == NULL || rsaDecryptCtx == NULL || aesDecryptCtx == NULL) {
return FAILURE;
}
// Init these here to make valgrind happy
EVP_CIPHER_CTX_init(rsaEncryptCtx);
EVP_CIPHER_CTX_init(aesEncryptCtx);
EVP_CIPHER_CTX_init(rsaDecryptCtx);
EVP_CIPHER_CTX_init(aesDecryptCtx);
// Init RSA
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
if(EVP_PKEY_keygen_init(ctx) <= 0) {
return FAILURE;
}
if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
return FAILURE;
}
if(EVP_PKEY_keygen(ctx, &localKeypair) <= 0) {
return FAILURE;
}
EVP_PKEY_CTX_free(ctx);
// Init AES
aesKey = (unsigned char*)malloc(AES_KEYLEN/8);
aesIV = (unsigned char*)malloc(AES_KEYLEN/8);
unsigned char *aesPass = (unsigned char*)malloc(AES_KEYLEN/8);
unsigned char *aesSalt = (unsigned char*)malloc(8);
if(aesKey == NULL || aesIV == NULL || aesPass == NULL || aesSalt == NULL) {
return FAILURE;
}

#ifdef USE_PBKDF
// Get some random data to use as the AES pass and salt
if(RAND_bytes(aesPass, AES_KEYLEN/8) == 0) {
return FAILURE;
}
if(RAND_bytes(aesSalt, 8) == 0) {
return FAILURE;
}
if(EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), aesSalt, aesPass, AES_KEYLEN/8, AES_ROUNDS, aesKey, aesIV) == 0) {
return FAILURE;
}
#else
if(RAND_bytes(aesKey, AES_KEYLEN/8) == 0) {
return FAILURE;
}
if(RAND_bytes(aesIV, AES_KEYLEN/8) == 0) {
return FAILURE;
}
#endif
free(aesPass);
free(aesSalt);
return SUCCESS;
}

int Crypto::genTestClientKey() {
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
if(EVP_PKEY_keygen_init(ctx) <= 0) {
return FAILURE;
}
if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYLEN) <= 0) {
return FAILURE;
}
if(EVP_PKEY_keygen(ctx, &remotePubKey) <= 0) {
return FAILURE;
}
EVP_PKEY_CTX_free(ctx);
return SUCCESS;
}
