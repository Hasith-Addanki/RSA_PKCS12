#include "openssl1.h";
#include <openssl/applink.c>

int main()
{
    //const unsigned char msg[] = "Hello, world!";
    std::string msg = "Hello, world!";
    size_t msgLen = msg.length();

    std::string signedMsg;

    std::cout << "Message to be signed: \n\t";
    for (int i = 0; i < msgLen; i++)
        std::cout << msg[i];
    std::cout << std::endl << std::endl;

    SignatureHelper::GenerateSignature(msg, msgLen, signedMsg);

    std::cout << "Signed Message:\n\t" << signedMsg << std::endl;

    std::cout << "Verifying the signature: \n\t";

    bool authentic = SignatureHelper::VerifySignature(msg, msgLen, signedMsg);

    if (authentic) {
        std::cout << "Signature is authentic." << std::endl;
    }
    else {
        std::cout << "Signature is not authentic." << std::endl;
    }
    std::cout << std::endl;

    std::cout << "Verifying the signature with altered msg: " << std::endl;

    //const unsigned char msg2[] = "HELLO, WORLD!";
    std::string msg2 = "HELLO, WORLD!";
    size_t msgLen2 = msg2.length();

    std::cout << "\tAlterned msg: \n\t\t";
    for (int i = 0; i < msgLen2; i++)
        std::cout << msg2[i];
    std::cout << std::endl << "\t";

    authentic = SignatureHelper::VerifySignature(msg2, msgLen2, signedMsg);

    if (authentic) {
        std::cout << "Signature is authentic." << std::endl;
    }
    else {
        std::cout << "Signature is not authentic." << std::endl;
    }

    std::cout << "\nVerifying the signature with altered signature: " << std::endl;
    signedMsg = "modified-" + signedMsg;

    std::cout << "\nAlterned signature:\n\t" << signedMsg << std::endl;
    authentic = SignatureHelper::VerifySignature(msg, msgLen, signedMsg);

    if (authentic) {
        std::cout << "\tSignature is authentic." << std::endl;
    }
    else {
        std::cout << "\tSignature is not authentic." << std::endl;
    }
}