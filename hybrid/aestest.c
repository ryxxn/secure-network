
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <assert.h>
#include "aesenc.h"

void aes_file_enc_test(char* iFilename, char* oFilename, char* oRecoveredfile)
{
    FILE* ifp = NULL;
    FILE* ofp = NULL;
    int plaintext_len;
    int ciphertext_len;
    unsigned char* plaintext = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char* recovered = NULL;

    unsigned char mk[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    unsigned char iv_enc[AES_BLOCK_SIZE] = {0x00, };
    unsigned char iv_dec[AES_BLOCK_SIZE] = {0x00, };

    ifp = fopen(iFilename, "rb");
    assert(ifp != NULL);

    ofp = fopen(oFilename, "wb");
    assert(ofp != NULL);

    fseek(ifp, 0, SEEK_END);
    plaintext_len = ftell(ifp);
    fseek(ifp, 0, SEEK_SET);

    plaintext = (unsigned char*)calloc(plaintext_len, sizeof(unsigned char));
    assert(plaintext != NULL);

    ciphertext = (unsigned char*)calloc(plaintext_len+AES_BLOCK_SIZE, sizeof(unsigned char));
    assert(ciphertext != NULL);

    recovered = (unsigned char*)calloc(plaintext_len+AES_BLOCK_SIZE, sizeof(unsigned char));
    assert(recovered != NULL);

    if(fread(plaintext, 1, plaintext_len, ifp) == 0)
    {
        fprintf(stderr, "fread() error\n");
    }
    if(ifp != NULL)
    {
        fclose(ifp);
    }
    
    ciphertext_len = encrypt(plaintext, plaintext_len, mk, iv_enc, ciphertext);

    fwrite(ciphertext, 1, ciphertext_len, ofp);
    if(ofp != NULL)
    {
        fclose(ofp);
    }

    plaintext_len = decrypt(ciphertext, ciphertext_len, mk, iv_dec, recovered);

    ofp = fopen(oRecoveredfile, "wb");
    assert(ofp != NULL);

    fwrite(recovered, 1, plaintext_len, ofp);
    if(ofp != NULL)
    {
        fclose(ofp);
    }

    if(plaintext != NULL)
    {
        free(plaintext);
        plaintext = NULL;
    }
    if(ciphertext != NULL)
    {
        free(ciphertext);
        ciphertext = NULL;
    }
    if(recovered != NULL)
    {
        free(recovered);
        recovered = NULL;
    }
}

void aes_evp_test()
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len;
    int plaintext_len;
    unsigned char plaintext[256] = {0x00, };
    unsigned char ciphertext[256+AES_BLOCK_SIZE] = {0x00, };
    unsigned char recovered[256+AES_BLOCK_SIZE] = {0x00, };
    unsigned char mk[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    unsigned char iv_enc[AES_BLOCK_SIZE] = {0x00, };
    unsigned char iv_dec[AES_BLOCK_SIZE] = {0x00, };

    memset(plaintext, 'A', sizeof(plaintext));

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        handleErrors();
    }
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, mk, iv_enc))
    {
        handleErrors();
    }
    
    plaintext_len = sizeof(plaintext);
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        handleErrors();
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal(ctx, ciphertext+len, &len))
    {
        handleErrors();
    }
    ciphertext_len += len;

    printf("Plaintext:\n");
    BIO_dump_fp(stdout, (const char*)plaintext, plaintext_len);

    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext, ciphertext_len);

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, mk, iv_dec))
    {
        handleErrors();
    }
    
    if(1 != EVP_DecryptUpdate(ctx, recovered, &len, ciphertext, ciphertext_len))
    {
        handleErrors();
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal(ctx, recovered+len, &len))
    {
        handleErrors();
    }
    plaintext_len += len;

    printf("Recovered:\n");
    BIO_dump_fp(stdout, (const char*)recovered, plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
}

void aes_simple_test()
{
    AES_KEY aes_enc_key, aes_dec_key;
    unsigned char mk[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    unsigned char iv_enc[AES_BLOCK_SIZE] = {0x00, };
    unsigned char iv_dec[AES_BLOCK_SIZE] = {0x00, };

    unsigned char plaintext[256] = {0x00, };
    unsigned char ciphertext[256+AES_BLOCK_SIZE] = {0x00, };
    unsigned char recovered[256] = {0x00, };

    AES_set_encrypt_key(mk, 128, &aes_enc_key);
    AES_set_decrypt_key(mk, 128, &aes_dec_key);

    memset(plaintext, 'A', sizeof(plaintext));

    printf("Plaintext:\n");
    BIO_dump_fp(stdout, (const char*)plaintext, sizeof(plaintext));

    AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext), &aes_enc_key, iv_enc, AES_ENCRYPT);

    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, (const char*)ciphertext, sizeof(ciphertext));

    AES_cbc_encrypt(ciphertext, recovered, sizeof(ciphertext), &aes_dec_key, iv_dec, AES_DECRYPT);

    printf("Recovered:\n");
    BIO_dump_fp(stdout, (const char*)recovered, sizeof(recovered));

    if(0 != memcmp(plaintext, recovered, sizeof(plaintext)))
    {
        fprintf(stderr, "\n\nDecryption failed\n");
    }
    else
    {
        fprintf(stderr, "\n\nDecryption succeeded\n");
    }
}

int main(int argc, char* argv[])
{       
    //aes_simple_test();
    //aes_evp_test();
    aes_file_enc_test("script.txt", "encryptedscript.txt", "recovered.txt");
}

// EOF
