#include "openssl1.h";
#include <openssl/applink.c>

int main()
{
    const unsigned char msg[] = "Hello, world!";
    size_t msgLen = strlen((const char*)msg);

    std::string signedMsg;

    std::cout << "Message to be signed: \n\t";
    for (int i = 0; i < msgLen; i++)
        std::cout << msg[i];
    std::cout << std::endl << std::endl;

    GenerateSignature(msg, msgLen, signedMsg);

    std::cout << "Signed Message:\n\t" << signedMsg << std::endl;

    std::cout << "Verifying the signature: \n\t";

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
    std::cout << std::endl << "\t";

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