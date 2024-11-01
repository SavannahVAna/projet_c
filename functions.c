#include "passfun.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin){
    printf("pour quel site est ce mot de passe?\n");
    Mot_de_passe* ptr = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
    scanf("%s",ptr->Site);
    printf("Quel est votre login pour ce password?\n");
    scanf("%s",ptr->Login);
    printf("tappez votre mdp\n");
    scanf("%s",ptr->Password);
	printf("commendtaires?\n");
	scanf("%s", ptr->Commentaire);
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

void encrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]) {
    // Obtenir la taille du fichier
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    // Remettre le pointeur de fichier au début
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0, outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize * 2); // Prendre en compte le rembourrage potentiel

    // Lire le fichier
    fread(indata, sizeof(char), fsize, ifp); // Lire tout le fichier

    // Créer et initialiser le contexte de chiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Allocation dynamique
    if (ctx == NULL) {
        fprintf(stderr, "Erreur lors de l'allocation du contexte de chiffrement.\n");
        free(indata);
        free(outdata);
        return;
    }

    // Initialiser le chiffrement
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Erreur lors de l'initialisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    // Chiffrement
    if (EVP_EncryptUpdate(ctx, outdata, &outLen1, indata, fsize) != 1) {
        fprintf(stderr, "Erreur lors du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    if (EVP_EncryptFinal_ex(ctx, outdata + outLen1, &outLen2) != 1) {
        fprintf(stderr, "Erreur lors de la finalisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    // Écrire le résultat dans le fichier de sortie
    fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp);

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
    free(indata);
    free(outdata);
}

void decrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]) {
    // Obtenir la taille du fichier
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    // Remettre le pointeur de fichier au début
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0, outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize); // La taille de sortie ne doit pas être plus grande que celle de l'entrée

    // Lire le fichier
    fread(indata, sizeof(char), fsize, ifp); // Lire tout le fichier

    // Créer et initialiser le contexte de déchiffrement
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Allocation dynamique
    if (ctx == NULL) {
        fprintf(stderr, "Erreur lors de l'allocation du contexte de déchiffrement.\n");
        free(indata);
        free(outdata);
        return;
    }

    // Initialiser le déchiffrement
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Erreur lors de l'initialisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    // Déchiffrement
    if (EVP_DecryptUpdate(ctx, outdata, &outLen1, indata, fsize) != 1) {
        fprintf(stderr, "Erreur lors du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    if (EVP_DecryptFinal_ex(ctx, outdata + outLen1, &outLen2) != 1) {
        fprintf(stderr, "Erreur lors de la finalisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    // Écrire le résultat dans le fichier de sortie
    fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp);

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
    free(indata);
    free(outdata);
}

void affiche_mdp(Mot_de_passe* mdp){
	struct tm* local_time = localtime(&mdp->creation);
    char* date_str = (char*)malloc(100 * sizeof(char)); 
     if (date_str == NULL) {
        perror("Erreur d'allocation de mémoire");
        return;
    }
    struct tm* local_time2 = localtime(&mdp->modif);
    char* date_str2 = (char*)malloc(100 * sizeof(char)); 
     if (date_str == NULL) {
        perror("Erreur d'allocation de mémoire");
        return;
    }

	strftime(date_str, 100, "%d/%m/%Y %H:%M:%S", local_time);
    strftime(date_str2, 100, "%d/%m/%Y %H:%M:%S", local_time2);
	printf("Entrée %d :\ndate d'ajout : %s\ndate de modif : %d\nsite : %s\nlogin : %s\npassword : %s\ncommentaires : %s", mdp->ID, date_str, date_str2,mdp->Site, mdp->Login, mdp->Password, mdp->Commentaire);
	free(date_str);
    free(date_str2);
}

void affiche_list(Mot_de_passe* mdp){
	Mot_de_passe* tmp = mdp;
	while (tmp != NULL)
	{
		affiche_mdp(tmp);
		tmp = tmp->ptr;
	}
	
}

Mot_de_passe* select_mdp(Mot_de_passe* head, int idex){
	 while (head != NULL && head->ID != idex){
        head = head->ptr;
    }
    return head;
}

//I WILL TREAT HER BETTER THTAN YOU EVER WILL JUSTE YOU WATCH

Mot_de_passe* recup_list(FILE* fiel) {
    Mot_de_passe* head = NULL;
    Mot_de_passe* prev = NULL;
    Mot_de_passe temp;

    while (fread(&temp, sizeof(Mot_de_passe), 1, fiel) == 1) {
        Mot_de_passe* new_node = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
        if (new_node == NULL) {
            perror("Memory allocation failed");
            fclose(fiel);
            return head;  // Retourner la liste partielle en cas de problème d'allocation
        }
        // Copier les informations lues dans le nouveau noeud
        *new_node = temp;  
        new_node->ptr = NULL;  

        // Si la liste est vide, ce nouvel élément devient la tête
        if (head == NULL) {
            head = new_node;
        } else {
            prev->ptr = new_node;  
        }

        prev = new_node;  
    }

    fclose(fiel);
    return head; 
}
