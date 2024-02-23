#ifndef SIGNATUREHELPER_H
#define SIGNATUREHELPER_H

#include <iomanip>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <algorithm>
#include <utility>
#include <cstdlib>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

class SignatureHelper {
public:
    static void GenerateSignature(const unsigned char* msg,
        size_t msgLen,
        std::string& signedMsg);
    
    static bool VerifySignature(const unsigned char* msg,
        size_t msgLen,
        const std::string& signedMsg);

private:
    static size_t calcDecodeLength(const char* b64input);

    static void Base64Encode(const unsigned char* Buffer,
        size_t Length,
        std::string& Base64Text);

    static void Base64Decode(const std::string& Base64Message,
        unsigned char** Buffer,
        int* Length);

    static EVP_PKEY* GetPrivatePublicKeyFromPKCS12(std::string key);

    static bool RSASign(EVP_PKEY* priKey,
        const unsigned char* Msg,
        size_t MsgLen,
        unsigned char** EncMsg,
        size_t* MsgLenEnc);

    static bool RSAVerifySignature(EVP_PKEY* pubKey,
        unsigned char* MsgHash,
        size_t MsgHashLen,
        const unsigned char* Msg,
        size_t MsgLen,
        bool* Authentic);
};
#endif // !SIGNATUREHELPER_H