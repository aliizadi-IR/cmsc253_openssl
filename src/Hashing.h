#ifndef HASHING_H
#define HASHING_H

#include <string>
#include <cstdio>
#include <stdlib.h>
#include <iostream>

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>

using namespace std;

class Hashing
{
    public:
        Hashing();
        void hashSHA1( string source );
        void hashSHA256( string source );
        void hashSHA512( string source );
        void hashFileHandling( string source, string cipherName, const EVP_MD* hashMd )
        {
            FILE *fIN, *fOUT;
            const char* READ = "rb";
            const char* WRITE = "w";
            string HASH_NAME = ( string( "hash_" ) + cipherName ) + ".txt";

            cout << "Hashing " << source << " using " << cipherName << " and storing in " << HASH_NAME << endl;
            // First encrypt the file
            fIN = fopen( source.c_str(), READ ); //File to be encrypted; plain text
            fOUT = fopen( HASH_NAME.c_str(), WRITE ); //File to be written; cipher text

            hashProcess( fIN, fOUT, hashMd );

            fclose( fIN );
            fclose( fOUT );
            cout << "Hashing complete" << endl << endl;
        }
    protected:
    private:

        void handleErrors()
        {
            ERR_print_errors_fp( stderr );
        }

        /**
         * Hash utilizing the given cipher.
         *
         * @param ifp input file where the data will read
         * @param ofp output file where the data will be written
         * @param hashMd the message digest algorithm being used
         */
        void hashProcess( FILE *ifp, FILE *ofp, const EVP_MD* hashMd ) {

            const unsigned BUFFER_SIZE = 4096;
            unsigned char readBuffer[ EVP_MAX_MD_SIZE ];
            unsigned char *messageDigest;
            unsigned blocksize;
            int outputLength;

            EVP_MD_CTX* ctx = EVP_MD_CTX_create();
            EVP_DigestInit_ex( ctx, hashMd, NULL );

            blocksize = EVP_MD_CTX_block_size( ctx );
            messageDigest = malloc( BUFFER_SIZE + blocksize );

            size_t numRead;
            while( ( numRead = fread( readBuffer, sizeof(unsigned char), BUFFER_SIZE, ifp ) ) != 0 )
            {
                // Read in data in blocks until EOF. Update the ciphering with each read.
                if( 1 != EVP_DigestUpdate( ctx, readBuffer, numRead ) )
                {
                    cout << "Error in update" << endl;
                    handleErrors();
                    break;
                }
            }

            cout << "Finalizing.." << endl;
            // Now cipher the final block and write it out.
            if( 1 != EVP_DigestFinal_ex( ctx, messageDigest, &outputLength) )
            {
                cout << "Error in finalizing" << endl;
                handleErrors();
            }
            else
            {
                cout << "Done finalizing: " << outputLength << endl;
                for( int i = 0; i < outputLength; i++ )
                {
                    printf( "%02x", messageDigest[i] );
                    fprintf( ofp, "%02x", messageDigest[i] );
                }
                printf("\n");
            }

            // Free memory
            free( messageDigest );
            free( readBuffer );
            EVP_MD_CTX_destroy( ctx );
        }
};

#endif // HASHING_H
