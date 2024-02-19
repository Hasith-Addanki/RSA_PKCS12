// openssl1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
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
static bool RSASign(RSA* rsa,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {

    EVP_MD_CTX* rsaSignCtx = EVP_MD_CTX_create();

    EVP_PKEY* priKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa); // Note that rsa and priKey are freed when rsaSignCtx is freed.

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


// Verify Message Against Signature We Have
static bool RSAVerifySignature(RSA* rsa,
    unsigned char* MsgHash,
    size_t MsgHashLen,
    const unsigned char* Msg,
    size_t MsgLen,
    bool* Authentic) {
    *Authentic = false;
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);

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

void printSignature(const unsigned char* signature, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // Print each byte as a two-digit hexadecimal number
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(signature[i]);
    }
    std::cout << std::dec << std::endl;
}

int main()
{
    RSA* rsa = createPrivateRSA("F:/C++ Visual Studio/RSA - keys/private.pem");
    std::cout << "Hello World!\n";
    if (rsa == NULL) {
        std::cerr << "Failed to load private key" << std::endl;
        return 1;
    }
    
    const unsigned char msg[] = "Hello, world!";
    size_t msgLen = strlen((const char*)msg);

    // Variables to store the signature
    unsigned char* signature;
    size_t signatureLen;

    // Call RSASign function
    if (!RSASign(rsa, msg, msgLen, &signature, &signatureLen)) {
        std::cerr << "Failed to create digital signature" << std::endl;
        RSA_free(rsa); // Don't forget to free RSA object
        return 1;
    }

    // Print the signed message (signature)
    std::cout << "Signed message: "<<std::endl;
    
    //std::cout << static_cast<unsigned>(*signature) << std::endl;
    // 
    // Free RSA object and signature

    printSignature(signature,signatureLen);

    std::cout << std::endl;
    //std::cout << rsa;
    //RSA_free(rsa);

    RSA* rsaPublic = createPublicRSA("F:/C++ Visual Studio/RSA - keys/public.pem");
    if (rsaPublic == nullptr) {
        std::cerr << "Failed to load public key" << std::endl;
        return 1;
    }

    const unsigned char msg2[] = "Hello, world2!";
    size_t msgLen2 = strlen((const char*)msg2);

    unsigned char* signature2;
    size_t signatureLen2;

    // Call RSASign function
    if (!RSASign(rsa, msg2, msgLen2, &signature2, &signatureLen2)) {
        std::cerr << "Failed to create digital signature" << std::endl;
        RSA_free(rsa); // Don't forget to free RSA object
        return 1;
    }

    std::cout << "Signature of unauthenticated  msg"<<std::endl;

    printSignature(signature2, signatureLen2);
    std::cout << std::endl;

    bool authentic;
    if (!RSAVerifySignature(rsaPublic, signature, signatureLen, msg2, msgLen2, &authentic)) {
        std::cerr << "Failed to verify signature" << std::endl;
        RSA_free(rsaPublic); // Don't forget to free RSA object
        return 1;
    }

    if (authentic) {
        std::cout << "Signature is authentic." << std::endl;
    }
    else {
        std::cout << "Signature is not authentic." << std::endl;
    }

    // Free RSA object
    RSA_free(rsaPublic);
    RSA_free(rsa);

    OPENSSL_free(signature);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
