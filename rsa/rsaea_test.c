#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/bn.h>

int rsaes_simple_test();

int main(int argc, char *argv[])
{
    rsaes_simple_test();
    return 0;
}

static int _pad_unknown(void)
{
  unsigned long l;
  while ((l = ERR_get_error()) != 0)
    if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
      return 1;

  return 0;
}

int rsaes_simple_test()
{
  int ret = 1;
  RSA* rsa;
  unsigned char ptext[256] = {0x00, };
  unsigned char ctext[256] = {0x00, };
  unsigned char ptext_ex[] = "Hello, World!";
  unsigned char ctext_es[256] = {0x00, };
  int plen = sizeof(ptext_ex) - 1;
  int clen = 0;
  int num;
  BIO *bp_public = NULL, *bp_private = NULL;
  unsigned long e_value = RSA_F4;
  BIGNUM *exponent_e = BN_new();

  rsa = RSA_new();

  BN_set_word(exponent_e, e_value);

  if (!RSA_generate_key_ex(rsa, 2048, exponent_e, NULL))
  {
    fprintf("RSA_generate_key_ex failed\n");
  }
  bp_public = BIO_new_file("public.pem", "w+");
  ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
  if (ret != 1) goto err;

  bp_private = BIO_new_file("private.pem", "w+");
  ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

  if (ret != 1) {
    ret = -1;
    goto err;
  }
  printf("\nplaintext\n");
  BIO_dump_fp(stdout, (const char*)ptext_ex, plen);

  num = RSA_public_encrypt(plen, ptext_ex, ctext, rsa, RSA_PKCS1_OAEP_PADDING);
  if(num == -1)
  {
    fprintf(stderr, "RSA_public_encrypt failed\n");
    ret = -1;
    goto err;
  }

  printf("\nciphertext\n");
  BIO_dump_fp(stdout, (const char*)ctext, num);

  num = RSA_private_decrypt(num, ctext, ptext, rsa, RSA_PKCS1_OAEP_PADDING);

  if (num != plen || memcmp(ptext, ptext_ex, plen) != 0)
  {
    fprintf(stderr, "RSA_private_decrypt failed\n");
    ret = -1;
    goto err;
  }

  printf("\nrecovered\n");
  BIO_dump_fp(stdout, (const char*)ptext, num);

err:
  RSA_free(rsa);
  BIO_free_all(bp_public);
  BIO_free_all(bp_private);
  return ret;
}