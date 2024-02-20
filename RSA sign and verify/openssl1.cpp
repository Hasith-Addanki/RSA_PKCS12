// openssl1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "openssl1.h";

static RSA* createPrivateRSA(std::string key) {
    RSA* rsa = NULL;
    const char* c_string = key.c_str();
    BIO* keybio = BIO_new_file(c_string, "r");
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    if (keybio) {
        BIO_free(keybio);
    }
    return rsa;
}

static RSA* createPublicRSA(std::string key) {
    RSA* rsa = NULL;
    BIO* keybio;
    const char* c_string = key.c_str();
    keybio = BIO_new_file(c_string, "r");
    if (keybio == NULL) {
        return 0;
    }
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    if (keybio) {
        BIO_free(keybio);
    }
    return rsa;
}

// Create Digital Hash (Signature) For Given Msg and Private Key
static bool RSASign(EVP_PKEY* priKey,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {

    EVP_MD_CTX* rsaSignCtx = EVP_MD_CTX_create();

    // Create Signing Context using a SHA-256 hashing function
    if (EVP_DigestSignInit(rsaSignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
        return false;
    }
    if (EVP_DigestSignUpdate(rsaSignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(rsaSignCtx, NULL, MsgLenEnc) <= 0) {
        return false;
    }
    *EncMsg = (unsigned char*)OPENSSL_malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(rsaSignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }

    // Free MD_CTX (also free's RSA and PKEY objects)
    EVP_MD_CTX_destroy(rsaSignCtx);

    return true;
}

static EVP_PKEY* GetPrivatePublicKeyFromPKCS12(std::string key) {
    FILE* p12_file = NULL;
    PKCS12* p12;
    X509* cert;
    EVP_PKEY* privateKey = NULL;
    EVP_PKEY* publicKey = NULL;

    char* p12_filename = "F:/C++ Visual Studio/RSA - keys/pkcs12-certificate.p12";
    if (p12_filename) {
        p12_file = fopen(p12_filename, "rb");
        if (!p12_file)
            return 0;
    }
    else
        return 0;

    p12 = d2i_PKCS12_fp(p12_file, NULL);
    if (!p12) {
        if (p12_file)
            fclose(p12_file);
        return 0;
    }

    const char* p12_key = "Hasith18*";

    if (!PKCS12_parse(p12, p12_key, &privateKey, &cert, NULL)){
        if (cert)
            X509_free(cert);
        if (p12)
            PKCS12_free(p12);
        if (p12_file)
            fclose(p12_file);
        if (privateKey)
            EVP_PKEY_free(privateKey);
        return 0;
    }

    publicKey = X509_get_pubkey(cert);
    //return (key == "private") ? privateKey:publicKey;
    if (key == "private")
        return privateKey;
    else if (key == "public")
        return publicKey;
    else
        return NULL;
}

// Verify Message Against Signature We Have
static bool RSAVerifySignature(EVP_PKEY* pubKey,
    unsigned char* MsgHash,
    size_t MsgHashLen,
    const unsigned char* Msg,
    size_t MsgLen,
    bool* Authentic) {
    *Authentic = false;

    EVP_MD_CTX* rsaVerifyCtx = EVP_MD_CTX_create();

    // Verifying the digest/hashcode using the SHA-256 hashing function
    if (EVP_DigestVerifyInit(rsaVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(rsaVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(rsaVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus == 1) {
        *Authentic = true;
        EVP_MD_CTX_destroy(rsaVerifyCtx);
        return true;
    }
    else if (AuthStatus == 0) {
        *Authentic = false;
        EVP_MD_CTX_destroy(rsaVerifyCtx);
        return true;
    }
    else {
        *Authentic = false;
        EVP_MD_CTX_destroy(rsaVerifyCtx);
        return false;
    }
}

void Base64Encode(const unsigned char *Buffer, size_t Length, std::string &Base64Text) {
    char* base64Ch;
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, Buffer, Length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_CLOSE);

    base64Ch = (char*)malloc(bufferPtr->length + 1);
    memcpy(base64Ch, bufferPtr->data, bufferPtr->length);
    base64Ch[bufferPtr->length] = '\0';

    Base64Text = base64Ch;

    free(base64Ch);
    BIO_free_all(bio);
}

static size_t calcDecodeLength(const char* b64input) {
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
        padding = 2;
    else if (b64input[len - 1] == '=')
        padding = 1;
    return (len * 3) / 4 - padding;
}

void Base64Decode(const std::string& Base64Message, unsigned char** Buffer, int *Length) {
    const char* Base64MessageCh = Base64Message.c_str();

    BIO* bio, * b64;

    int decodeLen = calcDecodeLength(Base64MessageCh);
    *Buffer = (unsigned char*)malloc(decodeLen + 1);
    (*Buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(Base64MessageCh, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *Length = BIO_read(bio, *Buffer, strlen(Base64MessageCh));
    BIO_free_all(bio);
}

void GenerateSignature(const unsigned char* msg,
    size_t msgLen,
    std::string& signedMsg) {
    
    EVP_PKEY* privateKey = GetPrivatePublicKeyFromPKCS12("private");
    if (privateKey == NULL) {
        std::cerr << "Failed to load private key" << std::endl;
        return;
    }

    // Variables to store the signature
    unsigned char* signature;
    size_t signatureLen;

    // Call RSASign function
    if (!RSASign(privateKey, msg, msgLen, &signature, &signatureLen)) {
        std::cerr << "Failed to create digital signature" << std::endl;
        //RSA_free(rsa); // Don't forget to free RSA object
        EVP_PKEY_free(privateKey);
        return;
    }

    Base64Encode(signature, signatureLen, signedMsg);

    EVP_PKEY_free(privateKey);
    OPENSSL_free(signature);
}

bool VerifySignature(const unsigned char* msg,
    size_t msgLen, 
    const std::string& signedMsg) {
    
    EVP_PKEY* publicKey = GetPrivatePublicKeyFromPKCS12("public");
    if (publicKey == nullptr) {
        std::cerr << "Failed to load public key" << std::endl;
        return false;
    }

    unsigned char* signature;
    int signatureLen;

    Base64Decode(signedMsg, &signature, &signatureLen);

    bool authentic = false;
    if (!RSAVerifySignature(publicKey, signature, signatureLen, msg, msgLen, &authentic)) {
        std::cerr << "Failed to verify signature" << std::endl;
        EVP_PKEY_free(publicKey); 
        return false;
    }

    EVP_PKEY_free(publicKey);
    
    return authentic;
}

int main()
{
    const unsigned char msg[] = "Hello, world!";
    size_t msgLen = strlen((const char*)msg);

    std::string signedMsg;
    
    std::cout << "Message to be signed: \n\t";
    for (int i = 0; i < msgLen; i++)
        std::cout << msg[i];
    std::cout << std::endl<<std::endl;

    GenerateSignature(msg, msgLen, signedMsg);

    std::cout << "Signed Message:\n\t" << signedMsg << std::endl;

    std::cout << "Verifying the signature: \n\t" ;

    bool authentic = VerifySignature(msg, msgLen, signedMsg);

    if (authentic) {
        std::cout << "Signature is authentic." << std::endl;
    }
    else {
        std::cout << "Signature is not authentic." << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Verifying the signature with altered msg: " << std::endl;

    const unsigned char msg2[] = "HELLO, WORLD!";
    size_t msgLen2 = strlen((const char*)msg2);

    std::cout << "\tAlterned msg: \n\t\t";
    for (int i = 0; i < msgLen2; i++)
        std::cout << msg2[i];
    std::cout << std::endl<<"\t";

    authentic = VerifySignature(msg2, msgLen2, signedMsg);

    if (authentic) {
        std::cout << "Signature is authentic." << std::endl;
    }
    else {
        std::cout << "Signature is not authentic." << std::endl;
    }

    std::cout << "\nVerifying the signature with altered signature: " << std::endl;
    signedMsg = "modified-" + signedMsg;

    std::cout << "\nAlterned signature:\n\t" << signedMsg << std::endl;
    authentic = VerifySignature(msg, msgLen, signedMsg);

    if (authentic) {
        std::cout << "\tSignature is authentic." << std::endl;
    }
    else {
        std::cout << "\tSignature is not authentic." << std::endl;
    }
}
