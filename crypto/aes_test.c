#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>

void aes_evp_test();

int main(){
  printf("AES EVP Test:\n");
  aes_evp_test();
  return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void aes_evp_test()
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  int plaintext_len;

  unsigned char plaintext[256] = {0x00, };
  unsigned char ciphertext[256 + AES_BLOCK_SIZE] = {0x00, };
  unsigned char recovered[256] = {0x00, };

  unsigned char mk[16] = {0x00, 0x01, 0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};

  unsigned char iv_enc[AES_BLOCK_SIZE] = {0x00, };
  unsigned char iv_dec[AES_BLOCK_SIZE] = {0x00, };

  memcpy(iv_dec, iv_enc, sizeof(iv_enc));
  memset(plaintext, 'A', sizeof(plaintext));

  if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, mk, iv_enc))
    handleErrors();

  plaintext_len = sizeof(plaintext);

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();

  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();

  ciphertext_len += len;

  printf("\n\nplaintext:\n");
  BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);

  printf("\nciphertext:\n");
  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, mk, iv_dec))
    handleErrors();

  if (1 != EVP_DecryptUpdate(ctx, recovered, &len, ciphertext, ciphertext_len))
    handleErrors();

  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, recovered + len, &len)) handleErrors();

  plaintext_len += len;

  printf("\n\nrecovered:\n");
  BIO_dump_fp(stdout, (const char *)recovered, plaintext_len);

  EVP_CIPHER_CTX_free(ctx);

}