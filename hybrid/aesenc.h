
#ifndef _AESENC_H_
#define _AESENC_H_

void handleErrors(void);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char *iv, unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertextg_len, unsigned char* key, unsigned char *iv, unsigned char* recovered);

#endif

