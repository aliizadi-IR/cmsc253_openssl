#ifndef RSA_H
#define RSA_H

#include <string>
#include <cstdio>
#include <stdlib.h>
#include <iostream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define RSA_KEY_2048 2048

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

using namespace std;

class RSAUsage
{
    public:
        RSAUsage();
        void generateRSAPair( string pubkeyName, string privKeyName );
        void encrypt( string source, string pubkeyName, string outputName );
        void decrypt( string source, string privKeyName, string outputName );
    protected:
        void handleErrors()
        {
            ERR_print_errors_fp( stderr );
            abort();
        }
    private:
};

#endif // RSA_H
