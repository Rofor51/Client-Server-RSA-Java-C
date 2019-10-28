#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <unistd.h>


#define PORT PORTHERE


int padding = RSA_PKCS1_PADDING;

RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
  
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
   
  
 
    return rsa;
}

int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,RSA_PKCS1_PADDING);
    return result;
}

void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}



void main() {
	int sockfd;
	struct sockaddr_in serverAddr;
	int clientSocket;
	char rcvBuffer[1024];
	int newSocket;
	struct sockaddr_in newAddr;

	socklen_t addr_size;
	char plainText[1024/8] = "Encrypt this, man.!"; 



	unsigned char encrypted[2050]={};
	

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	printf("Server socket created!");
	memset(&serverAddr, '\0',sizeof(serverAddr));

	serverAddr.sin_family =AF_INET;
	serverAddr.sin_port =htons(PORT);
	serverAddr.sin_addr.s_addr = inet_addr("IP");

	bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
	
	listen(sockfd, 5);
	printf("Listening...");

	newSocket = accept(sockfd, (struct sockaddr*)&newAddr,&addr_size);

	recv(newSocket,rcvBuffer,1024,0);
	printf("%s",rcvBuffer);


	
	int length = public_encrypt(plainText,strlen(plainText),rcvBuffer,encrypted);
	printf("Encrypted text =%s\n",encrypted);

	char base64a[128];
        int encode_str_size = EVP_EncodeBlock(base64a,encrypted,strlen(encrypted));
        printf("BASE64 TEST [%s]", base64a);
	
	char *output = base64((unsigned char*)encrypted, strlen(encrypted));
	printf("Base64: '%s'", output);
	 write(newSocket,base64a,strlen(base64a));
  	free(output);
	

	plainText[strlen(plainText)] = '\0';
	encrypted[strlen(encrypted)] = '\0';
	

	




	

	

	 
  	

	


}


