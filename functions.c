#include "passfun.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>

Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin){
    printf("pour quel site est ce mot de passe?\n");
    Mot_de_passe* ptr = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
    scanf("%s",&ptr->Site);
    printf("Quel est votre login pour ce password?\n");
    scanf("%s",&ptr->Login);
    printf("tappez votre mdp\n");
    scanf("%s",&ptr->Password);
    ptr->ptr = ancin;
    ptr->ID = ID;
    time(&ptr->creation);
    time(&ptr->modif);
    return ptr;

}

int aes_encrypt (const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		printf("Error initializing AES context. \n");
		return -1;
	}
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){
		printf("Error initializing AES encryption. \n");
		return -1;
	}

	if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		printf("Erruro during AES encryption. \n");
		return -1;
	}
	ciphertext_len = len;

	if (1!= EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		printf("Erruro finalizing AES encryption. \n");
		return -1;
	}
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;

}


int aes_decrypt (const unsigned char *ciphertext, int cipherlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		printf("Error initializing AES context. \n");
		return -1;
	}
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)){
		printf("Error initializing AES decryption. \n");
		return -1;
	}

	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen)) {
		printf("Erruro during AES decryption. \n");
		return -1;
	}
	ciphertext_len = len;

	if (1!= EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
		printf("Erruro finalizing AES decryption. \n");
		return -1;
	}
	ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return ciphertext_len;

}

void sha1_hash(const char *input, unsigned int inputlen, unsigned char *output, unsigned int *output_length) {

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) { printf("Failed to allocate context\n"); return; }
	
	const EVP_MD *md = EVP_sha1();
	EVP_DigestInit_ex(ctx, md, NULL);
	EVP_DigestUpdate(ctx, input, inputlen);
	EVP_DigestFinal_ex(ctx, output, output_length);
	EVP_MD_CTX_free(ctx);

}

void decryptfromfile(){

	FILE *file = NULL;
	file = fopen("key.log","rb");
	if (file == NULL){
		printf("Impossible to open file. It either don't exist or has a problem.");
		return;
	}
	
	int byte;
    	while ((byte = fgetc(file)) == 0x00) {
   	}
	fseek(file,-1,SEEK_CUR);
	AEScipher *aescipher = (AEScipher*) malloc(sizeof(AEScipher));
	memset(aescipher,0,sizeof(AEScipher));
	if (fread(aescipher,sizeof(AEScipher),1,file) != 1) {
		free(aescipher);
		printf("No AES structure in this file.\n");
	}
	
	char cipher[500];
	printf("Enter cipher : ");
	fgets(cipher,500,stdin);
	cipher[strcspn(cipher,"\n")] = 0;

	unsigned char cipherbin[strlen(cipher)/2];
	unsigned int cipherlen = hex_to_bin(cipher,cipherbin);
	unsigned char plain[strlen(cipher)];
	
	print_hexa(aescipher->IV,16);
	print_hexa(aescipher->key,16);
	int plainlen = aes_decrypt(cipherbin,cipherlen,aescipher->key,aescipher->IV,(unsigned char*)plain);
	
	if (plainlen!=-1){
		printf("PlainLen = %d\n",plainlen);
       	printf("Message (hex) : "); print_hexa(plain,plainlen);
		printf("\nMessage (raw) : %s\n",plain);
	}	
	free(aescipher);
	fclose(file);
}

int hex_to_bin(const char* hex_string, unsigned char* bin_output) {
    	int len = strlen(hex_string);
    	int bin_len = len / 2; 

    	for (int i = 0; i < bin_len; i++) {
        	sscanf(hex_string + 2*i, "%2hhx", &bin_output[i]);
    	}
	return bin_len;
}
