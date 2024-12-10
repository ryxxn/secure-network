
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
#include "aesencrypt.h"
#include "msg.h"

void error_handling(char *msg)
{
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

#define BUF_SIZE 	128

int main(int argc, char* argv[])
{
	int cnt_i;
	int sock;
	struct sockaddr_in serv_addr;
	int len;

	APP_MSG msg_in;
	APP_MSG msg_out;
	char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0x00, };

	unsigned char key[AES_KEY_128] = {0x00, };
	unsigned char iv[AES_KEY_128] = {0x00, };
	unsigned char encrypted_key[AES_KEY_128] = {0x00, };

	BIO *rpub = NULL;
	RSA *rsa_pubkey = NULL;

	int n;
	int plaintext_len;
	int ciphertext_len;

	RAND_poll();
	RAND_bytes(key, sizeof(key));

	for (cnt_i = 0; cnt_i < AES_KEY_128; cnt_i++)
	{
		iv[cnt_i] = (unsigned char)cnt_i;
	}

	if(argc != 3)
	{
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if(sock == -1	)
		error_handling("socket() error");

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

	if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("connect() error");

	/**
	 * 서로 공개키 요청 메시지 전송
	 * setup process
	 * sending PUBLIC_KEY_REQUEST msg
	 */
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = PUBLIC_KEY_REQUEST;
	msg_out.type = htonl(msg_out.type);

	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n != -1)
		error_handling("writen() error");

	/**
	 * 서버로부터 공개키 메시지 수신
	 * receiving PUBLIC_KEY msg
	 * */ 
	memset(&msg_in, 0, sizeof(msg_in));
	n = readn(sock, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);

	if(n == -1)
		error_handling("readn() error");
	else if(n == 0)
		error_handling("reading EOF");

	if(msg_in.type != PUBLIC_KEY)
		error_handling("invalid message type");
	else {
		BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len, msg_in.msg_len);

		/**
		 * 서버로부터 공개키 메시지를 RSA 타입으로 변환
		 */
		rpub = BIO_new_mem_buf(msg_in.payload, msg_in.msg_len);
		BIO_write(rpub, msg_in.payload, msg_in.msg_len);
		if(!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL))
			error_handling("PEM_read_bio_RSAPublicKey() error");
	}

	/**
	 * sending ENCRYPTED_KEY msg
	 */
	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = ENCRYPTED_KEY;
	msg_out.type = htonl(msg_out.type);
	/**
	 * 클라이언트는 랜덤하게 생성한 키를
	 * 서버의 공개키로 암호화하여 서버로 전송
	 */
	msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_PADDING);
	msg_out.msg_len = htonl(msg_out.msg_len);

	n = writen(sock, &msg_out, sizeof(APP_MSG));
	if(n != -1)
		error_handling("writen() error");

	getchar();

	while(1)
	{
		// input a message
		printf("Input a message > \n");
		if(fgets(plaintext, BUFSIZE+1, stdin) == NULL)
			break;
		
		// remove '\n'
		len = strlen(plaintext);
		if(plaintext[len-1] == '\n')
			plaintext[len-1] = '\0';
		if(strlen(plaintext) == 0)
			break;
		
		memset(&msg_out, 0, sizeof(msg_out));
		msg_out.type = ENCRYPTED_MSG;
		msg_out.type = htonl(msg_out.type);

		/**
		 * 사용자가 입력한 메시지를 암호화하여 서버로 전송
		 */
		ciphertext_len = encrypt((unsigned char*)plaintext, len, key, iv, msg_out.payload);
		msg_out.msg_len = htonl(ciphertext_len);

		// sending the inputed message
		n = writen(sock, &msg_out, sizeof(APP_MSG));
		if(n != -1){
			error_handling("writen() error");
			break;
		}

		//receiving a message from the server
		n = readn(sock, &msg_in, sizeof(APP_MSG));

		if(n == -1){
			error_handling("readn() error");
			break;
		}
		else if(n == 0){
			break;
		}

		msg_in.type = ntohl(msg_in.type);
		msg_in.msg_len = ntohl(msg_in.msg_len);

		switch(msg_in.type)
		{
			case ENCRYPTED_MSG:
				BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len, msg_in.msg_len);
				// 서버로부터 전송된 메시지를 복호화하여 출력
				plaintext_len = decrypt(msg_in.payload, msg_in.msg_len, key, iv, (unigned char *)plaintext);

				printf("* decryptedMsg: \n");
				BIO_dump_fp(stdout, (const char *)plaintext, plaintext_len);
				break;
			default:
				break;
		}
		// print the received message
		plaintext[plaintext_len] = '\0';
		printf("%s\n", plaintext);
	}

	close(sock);
	return 0;
}
