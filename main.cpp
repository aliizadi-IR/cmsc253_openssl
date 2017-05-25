#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

#include "SymmetricEncryption.h"
#include "Hashing.h"
#include "RSA.h"
#include "applink.c"

#define BUFFER 1024

int compareFile(FILE* file_compared, FILE* file_checked)
{
    bool diff = 0;
    int N = 65536;
    char* b1 = (char*) calloc (1, N+1);
    char* b2 = (char*) calloc (1, N+1);
    size_t s1, s2;

    do {
        s1 = fread(b1, 1, N, file_compared);
        s2 = fread(b2, 1, N, file_checked);

        if (s1 != s2 || memcmp(b1, b2, s1)) {
            diff = 1;
            break;
        }
      } while (!feof(file_compared) || !feof(file_checked));

    free(b1);
    free(b2);

    if (diff) return 0;
    else return 1;
}

int compareFileFromName( string orig, string compare )
{
    FILE* origFile = fopen( orig.c_str(), "r" );
    FILE* compFile = fopen( compare.c_str(), "r" );
    int ret = compareFile( origFile, compFile );
    fclose( origFile );
    fclose( compFile );
    return ret;
}

int readFile( string fileName, char* storage )
{
    FILE *fp = fopen( fileName.c_str(), "rb" );

    int numRead = 0;
    while( TRUE )
    {
        numRead = fread( storage, sizeof(unsigned char), BUFFER, fp );
        if ( numRead < BUFFER )
        {
            break;
        }
    }
    fclose( fp );
    return 0;
}

int main(int argc, char *argv[])
{
    /*
     * The following values are hardcoded for the purpose of files being produced
     * will be consistent.
     */
    /* A 256 bit key */
    unsigned char ckey[] = "01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char ivec[] = "0123456789012345";

    string symmetricKeyFile = "symmetric_key.txt";
    string ivFile = "iv_key.txt";

    // Write keys for convience, this should not be done in actual scenarios
    FILE* file = fopen( symmetricKeyFile.c_str(), "wb" );
    fwrite( &ckey, sizeof(unsigned char), strlen( ckey ), file );
    fclose( file );

    file = fopen( ivFile.c_str(), "wb" );
    fwrite( &ivec, sizeof(unsigned char), strlen( ivec ), file );
    fclose( file );

    string source = "lena512color.tiff";

    // 2. Pure symmetric encryption
    SymmetricEncryption symmetric( ckey, ivec );
    symmetric.cryptoAES128ECB( source );
    symmetric.cryptoAES128CBC( source );

    // 3. Pure Hashing
    Hashing hashing;
    hashing.hashSHA1( source );
    hashing.hashSHA256( source );
    hashing.hashSHA512( source );

    // 4. RSA
    string publicKey = "public_key.pem";
    string privateKey = "private_key.pem";

    string rsaEncryptedFileToBeSend = "rsa_encrypted_image.txt";
    /* We can't perform RSA on a file that contains large bytes of data, therefore we will first encrypt
     * the file using symmetric encryption, then we get the SHA-256 of the encrypted file. This hash will
     * now be the one that RSA encryption will perform to.
     */
    symmetric.encryptFileHandling( source, "RSA_ENCYPT_AES", rsaEncryptedFileToBeSend, EVP_aes_128_cbc() );
    hashing.hashFileHandling( rsaEncryptedFileToBeSend, "RSA_SHA_256", EVP_sha256() );

    RSAUsage usage;
    usage.generateRSAPair( publicKey, privateKey );

    string hashNotEncrypted = "hash_RSA_SHA_256.txt";
    string rsaHashFileToBeSend = "rsa_hash_encrypt2048.txt";
    string rsaKeyToBeSend = "rsa_key_encrypt2048.txt";
    string rsaIVToBeSend = "rsa_iv_encrypt2048.txt";
    /* hash_RSA_SHA_256.txt will be the generated file from the hash.
     * If there is communication rsa_hash_encrypt2048.txt will be the one to be sent.
     */
    usage.encrypt( hashNotEncrypted, publicKey, rsaHashFileToBeSend );
    usage.encrypt( symmetricKeyFile, publicKey, rsaKeyToBeSend );
    usage.encrypt( ivFile, publicKey, rsaIVToBeSend );

    //============== Supposed that transaction after here is in another PC ========================//

    string rsaHashDecrypted = "rsa_hash_decrypt2048.txt";
    string rsaKeyDecrypted = "rsa_key_decrypt2048.txt";
    string rsaIVDecrypted = "rsa_iv_decrypt2048.txt";
    /*
     * First we decrypt the sent file using RSA 2048. And the decrypted can be counter check with the hash
     * to ensure that it is the one sent.
     */
    usage.decrypt( rsaHashFileToBeSend, privateKey, rsaHashDecrypted );
    if( compareFileFromName( rsaHashDecrypted, hashNotEncrypted ) )
    {
        cout << "Hash is confirmed!" << endl;
        usage.decrypt( rsaKeyToBeSend, privateKey, rsaKeyDecrypted );

        unsigned char keyLine[ BUFFER ];
        readFile( rsaKeyDecrypted, keyLine );

        usage.decrypt( rsaIVToBeSend, privateKey, rsaIVDecrypted );

        unsigned char ivLine[ BUFFER ];
        readFile( rsaIVDecrypted, ivLine );

        SymmetricEncryption receiverDecryption( keyLine, ivLine );
        symmetric.decryptFileHandling( rsaEncryptedFileToBeSend, "RSA_DECYPT_AES", "rsa_final_image.tiff", EVP_aes_128_cbc() );
    }
    else
    {
        cout << "Hash is incorrect, do not proceed with RSA decryption." << endl;
    }

    EVP_cleanup();
    return 0;
}
