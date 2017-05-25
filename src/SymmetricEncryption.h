#ifndef SYMMETRICENCRYPTION_H
#define SYMMETRICENCRYPTION_H
#include <string>
#include <cstdio>
#include <stdlib.h>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

using namespace std;

class SymmetricEncryption
{
    public:
        SymmetricEncryption( unsigned char *ckey, unsigned char *ivec );
        void cryptoAES128ECB( string source );
        void cryptoAES128CBC( string source );

        void encryptFileHandling( string source, string cipherName, string encryptFileName, const EVP_CIPHER* encryptCipher )
        {
            FILE *fIN, *fOUT;
            cout << "Encrypting " << source << " using " << cipherName << " and storing in " << encryptFileName << endl;
            // First encrypt the file
            fIN = fopen( source.c_str(), "rb" ); //File to be encrypted; plain text
            fOUT = fopen( encryptFileName.c_str(), "wb" ); //File to be written; cipher text

            cryptoProcess( TRUE, fIN, fOUT, encryptCipher );

            fclose( fIN );
            fclose( fOUT );
            cout << "Encrypting complete" << endl << endl;
        }

        void decryptFileHandling( string encryptFileName, string cipherName, string decryptFileName, const EVP_CIPHER* decryptCipher )
        {
            FILE *fIN, *fOUT;
            cout << "decrypting " << encryptFileName << " using " << cipherName << " and storing in " << decryptFileName << endl;
            //Decrypt file now
            fIN = fopen( encryptFileName.c_str(), "rb" ); //File to be read; cipher text
            fOUT = fopen( decryptFileName.c_str(), "wb" ); //File to be written; cipher text

            cryptoProcess( FALSE, fIN, fOUT, decryptCipher );

            fclose( fIN );
            fclose( fOUT );
            cout << "Decrypting complete" << endl;
        }
    protected:

    private:
        unsigned char *key;
        unsigned char *iv;

        void handleErrors()
        {
            ERR_print_errors_fp( stderr );
        }

        /**
         * Encrypt or decrypt utilizing the given cipher. depending on flag 'willEncrypt'
         *
         * @param willEncrypt will encrypt or decrypt based on the value.
         * @param ifp input file where the data will read
         * @param ofp output file where the data will be written
         * @param cipher the cipher algorithm being used
         */
        void cryptoProcess( int willEncrypt, FILE *ifp, FILE *ofp, const EVP_CIPHER* cipher )
        {
            const unsigned BUFFER_SIZE = 4096;
            unsigned char *readBuffer = malloc( BUFFER_SIZE );
            unsigned char *cipherBuffer;
            unsigned blocksize;
            int outputLength;

            EVP_CIPHER_CTX& ctx = *( EVP_CIPHER_CTX_new() );

            if( 1 != EVP_CipherInit( &ctx, cipher, key, iv, willEncrypt ) )
            {
                handleErrors();
                abort();
            }

            blocksize = EVP_CIPHER_CTX_block_size( &ctx );
            cipherBuffer = malloc( BUFFER_SIZE + blocksize );

            while( TRUE )
            {
                // Read in data in blocks until EOF. Update the ciphering with each read.
                int numRead = fread( readBuffer, sizeof(unsigned char), BUFFER_SIZE, ifp );
                if( 1 != EVP_CipherUpdate( &ctx, cipherBuffer, &outputLength, readBuffer, numRead ) )
                {
                    handleErrors();
                    break;
                }
                else
                {
                    fwrite( cipherBuffer, sizeof(unsigned char), outputLength, ofp );
                }
                if ( numRead < BUFFER_SIZE )
                {
                    break;
                }
            }

            // Now cipher the final block and write it out.
            if( 1 != EVP_CipherFinal(&ctx, cipherBuffer, &outputLength) )
            {
                handleErrors();
            }
            else
            {
                fwrite( cipherBuffer, sizeof(unsigned char), outputLength, ofp );
            }

            // Free memory
            free( cipherBuffer );
            free( readBuffer );
            EVP_CIPHER_CTX_free( &ctx );
        }

        void cryptoFileHandling( string source, string cipherName, const EVP_CIPHER* encryptCipher, const EVP_CIPHER* decryptCipher )
        {
            FILE *fIN, *fOUT;
            string ENCRYPT_NAME = ( string( "encypt_" ) + cipherName ) + ".tiff";
            string DECRYPT_NAME = ( string( "decypt_" ) + cipherName ) + ".tiff";

            encryptFileHandling( source, cipherName, ENCRYPT_NAME, encryptCipher );

            decryptFileHandling( ENCRYPT_NAME, cipherName, DECRYPT_NAME, decryptCipher );
        }
};

#endif // SYMMETRICENCRYPTION_H
