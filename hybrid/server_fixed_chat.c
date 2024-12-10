

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "readnwrite.h"
#include "aesenc.h"
#include "msg.h"

void error_handling(char *message){
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

int main(int argc, char* argv[])
{
    int cnt_i;
	int serv_sock = -1;
	int clnt_sock = -1;
	
	struct sockaddr_in serv_addr;
	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size;

    APP_MSG msg_in;
    APP_MSG msg_out;

    char plaintext[BUFSIZE+AES_BLOCK_LEN] = {0x00, };
    int n;
    int len;
    int plaintext_len;
    int ciphertext_len;
	int publickey_len;
	int encryptedkey_len;

    unsigned char key[AES_KEY_128] = {0x00, };
	unsigned char iv[AES_KEY_128] = {0x00, };
	unsigned char buffer[BUFSIZE] = {0x00, };

	BIO *pb_public = NULL, *pb_private = NULL;
	BIO *pub = NULL;
	RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

    for(cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
    {
		iv[cnt_i] = (unsigned char)cnt_i;
    }

    if(argc!=2){
		printf("Usage : %s <port>\n", argv[0]);
		exit(1);
	}

    serv_sock=socket(PF_INET, SOCK_STREAM, 0);
	if(serv_sock == -1)
		error_handling("socket() error");
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=htonl(INADDR_ANY);
	serv_addr.sin_port=htons(atoi(argv[1]));
	
	if(bind(serv_sock, (struct sockaddr*) &serv_addr, 
		sizeof(serv_addr))==-1 )
		error_handling("bind() error"); 
	
	if(listen(serv_sock, 5)==-1)
		error_handling("listen() error");

	pb_public = BIO_new_file("public.pem", "r");
	if(!PEM_read_bio_RSAPublicKey(pb_public, &rsa_pubkey, NULL, NULL)){
		goto err;
	}

	pb_private = BIO_new_file("private.pem", "r");
	if(!PEM_read_bio_RSAPrivateKey(pb_private, &rsa_privkey, NULL, NULL)){
		goto err;
	}

    while(1)
    {
        clnt_addr_size=sizeof(clnt_addr);
		clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

        if(clnt_sock==-1){
			error_handling("accept() error");  
		}

        printf("\n[TCP Server] Client connected: IP=%s, port=%d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));

		// setup process
		memset(&msg_in, 0, sizeof(APP_MSG));
		n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);

		if(n == -1){
			error_handling("reand() error");
		}
		else if(n == 0){
			error_handling("reading EOF");
		}

		if(msg_in.type != PUBLIC_KEY_REQUEST)
		{
			error_handling("message error");
		}
		else
		{
			memset(&msg_out, 0, sizeof(APP_MSG));
			msg_out.type = PUBLIC_KEY;
			msg_out.type = htonl(msg_out.type);

			pub = BIO_new(BIO_s_mem());
			PEM_write_bio_RSAPublicKey(pub, rsa_pubkey);
			publickey_len = BIO_pending(pub);

			BIO_read(pub, msg_out.payload, publickey_len);
			msg_out.msg_len = htonl(publickey_len);

			n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
            if(n == -1){
				error_handling("write() error");
				break;
			}
		}
		
		memset(&msg_in, 0, sizeof(APP_MSG));
		n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));
		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);

		if(msg_in.type != ENCRYPTED_KEY)
		{
			error_handling("message error");
		}
		else
		{
			encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
			memcpy(key, buffer, encryptedkey_len);
		}
		
		getchar();

        while(1)
        {
            n = readn(clnt_sock, &msg_in, sizeof(APP_MSG));

            if(n == -1){
				error_handling("reand() error");
				break;
			}
			else if(n == 0){
				break;
			}

			msg_in.type = ntohl(msg_in.type);
            msg_in.msg_len = ntohl(msg_in.msg_len);

			switch (msg_in.type)
			{
			case ENCRYPTED_MSG:
				printf("\n* encryptedMsg: \n");
				BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);

				plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unsigned char*)plaintext);

				printf("\n* decryptedMsg: \n");
				BIO_dump_fp(stdout, (const char*)plaintext, plaintext_len);

				plaintext[plaintext_len] = '\0';
				printf("%s\n", plaintext);
				break;
			
			default:
				break;
			}

            // 
            printf("Input a message > \n");
			if(fgets(plaintext, BUFSIZE+1, stdin) == NULL){
				break;
			}

            // removing '\n' character
			len = strlen(plaintext);
			if(plaintext[len-1] == '\n'){
				plaintext[len-1] = '\0';
			}
			if(strlen(plaintext) == 0){
				break;
			}

            ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
			msg_out.type = ENCRYPTED_MSG;
			msg_out.type = htonl(msg_out.type);
            msg_out.msg_len = htonl(ciphertext_len);

            n = writen(clnt_sock, &msg_out, sizeof(APP_MSG));
            if(n == -1){
				error_handling("write() error");
				break;
			}	
        }
        close(clnt_sock);
        printf("[TCP Server] Client close: IP=%s, port=%d\n", 
						inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
    }

err:
    close(serv_sock);
    return 0;
}