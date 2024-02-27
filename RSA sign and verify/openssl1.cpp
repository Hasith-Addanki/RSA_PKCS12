// openssl1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "openssl1.h";

void SignatureHelper::GenerateSignature(std::string& msg, size_t msgLen, std::string& signedMsg)
{
    const unsigned char* msg_ch = (const unsigned char*) msg.c_str();
    EVP_PKEY* privateKey = GetPrivatePublicKeyFromPKCS12("private");
    if (privateKey == NULL) {
        std::cerr << "Failed to load private key" << std::endl;
        return;
    }

    // Variables to store the signature
    unsigned char* signature;
    size_t signatureLen;

    // Call RSASign function
    if (!RSASign(privateKey, msg_ch, msgLen, &signature, &signatureLen)) {
        std::cerr << "Failed to create digital signature" << std::endl;
        //RSA_free(rsa); // Don't forget to free RSA object
        EVP_PKEY_free(privateKey);
        return;
    }

    Base64Encode(signature, signatureLen, signedMsg);

    EVP_PKEY_free(privateKey);
    OPENSSL_free(signature);
}

bool SignatureHelper::VerifySignature(std::string& msg, size_t msgLen, const std::string& signedMsg)
{
    const unsigned char* msg_ch = (const unsigned char*)msg.c_str();

    EVP_PKEY* publicKey = GetPrivatePublicKeyFromPKCS12("public");
    if (publicKey == nullptr) {
        std::cerr << "Failed to load public key" << std::endl;
        return false;
    }

    unsigned char* signature;
    int signatureLen;

    Base64Decode(signedMsg, &signature, &signatureLen);

    bool authentic = false;
    if (!RSAVerifySignature(publicKey, signature, signatureLen, msg_ch, msgLen, &authentic)) {
        std::cerr << "Failed to verify signature" << std::endl;
        EVP_PKEY_free(publicKey);
        return false;
    }

    EVP_PKEY_free(publicKey);

    return authentic;
}

size_t SignatureHelper::calcDecodeLength(const char* b64input)
{
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
        padding = 2;
    else if (b64input[len - 1] == '=')
        padding = 1;
    return (len * 3) / 4 - padding;
}

void SignatureHelper::Base64Encode(const unsigned char* Buffer, size_t Length, std::string& Base64Text)
{
    char* base64Ch;
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
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

void SignatureHelper::Base64Decode(const std::string& Base64Message, unsigned char** Buffer, int* Length)
{
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

EVP_PKEY* SignatureHelper::GetPrivatePublicKeyFromPKCS12(std::string key)
{
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

    if (!PKCS12_parse(p12, p12_key, &privateKey, &cert, NULL)) {
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

bool SignatureHelper::RSASign(EVP_PKEY* priKey, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc)
{
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

bool SignatureHelper::RSAVerifySignature(EVP_PKEY* pubKey, unsigned char* MsgHash, size_t MsgHashLen, const unsigned char* Msg, size_t MsgLen, bool* Authentic)
{
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
    };
}
