#include "passfun.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>


Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin) {
    printf("pour quel site est ce mot de passe?\n");
    Mot_de_passe* ptr = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
    if (ptr == NULL) {
        perror("Erreur d'allocation de mémoire");
        return NULL;
    }
    scanf("%s", ptr->Site);
    printf("Quel est votre login pour ce password?\n");
    scanf("%s", ptr->Login);
    printf("tapez votre mdp\n");
    scanf("%s", ptr->Password);
    printf("commentaires?\n");
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

void sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("Erreur lors de l'initialisation du contexte SHA1\n");
        return;
    }

    const EVP_MD *md = EVP_sha1();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinal_ex(ctx, output, NULL);

    EVP_MD_CTX_free(ctx);
}

ij_vc* get_cipher(FILE* fp) {
    // Allocation de mémoire pour un nouvel objet ij_vc
    ij_vc* new_node = (ij_vc*)malloc(sizeof(ij_vc));
    if (new_node == NULL) {
        perror("Memory allocation failed");
        return NULL; // Retourner NULL en cas d'échec d'allocation
    }

    // Lecture d'un objet de type ij_vc dans new_node
    if (fread(new_node, sizeof(ij_vc), 1, fp) != 1) {
        perror("Failed to read structure from file");
        free(new_node);  // Libération de la mémoire en cas d'échec de lecture
        return NULL;
    }
    fclose(fp);
    return new_node;  // Retourner le pointeur vers la structure lue
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

void affiche_mdp(Mot_de_passe* mdp) {
    // Récupération des temps de création et de modification
    struct tm* local_time = localtime(&mdp->creation);
    char date_str[100]; 
    struct tm* local_time2 = localtime(&mdp->modif);
    char date_str2[100]; 

    // Formatage des dates
    strftime(date_str, sizeof(date_str), "%d/%m/%Y %H:%M:%S", local_time);
    strftime(date_str2, sizeof(date_str2), "%d/%m/%Y %H:%M:%S", local_time2);

    // Affichage des informations du mot de passe
    printf("Entrée %d :\ndate d'ajout : %s\ndate de modif : %s\nsite : %s\nlogin : %s\ncommentaires : %s",
           mdp->ID, date_str, date_str2, mdp->Site, mdp->Login, mdp->Commentaire);
}


void affiche_list(Mot_de_passe* mdp){
	Mot_de_passe* tmp = mdp;
	while (tmp != NULL)
	{
		affiche_mdp(tmp);
		tmp = tmp->ptr;
	}
	
}

Mot_de_passe* select_mdp(Mot_de_passe* hea, int idex){
    Mot_de_passe* head =hea;
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

void enregister(Mot_de_passe* mdp, FILE* file){
    Mot_de_passe* ptr = mdp->ptr;
    while(ptr != NULL){
        fwrite(ptr, sizeof(Mot_de_passe), 1, file);
        ptr = ptr->ptr;
    }
    fclose(file);
}

Mot_de_passe* read_file(FILE* file){
    Mot_de_passe* head = NULL;  // Tête de la liste
    Mot_de_passe* prev = NULL;  // Pointeur vers le nœud précédent
    Mot_de_passe temp;

  
    while (fread(&temp, sizeof(Mot_de_passe), 1, file) == 1) {
        
        Mot_de_passe* new_node = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
        if (new_node == NULL) {
            perror("Memory allocation failed");
            fclose(file);
            return head; 
        }

        
        *new_node = temp;  
        new_node->ptr = NULL;  

        
        if (head == NULL) {
            head = new_node;
        } else {
            prev->ptr = new_node;  
        }

        prev = new_node;  
    }

    fclose(file);
    return head; 
}

Mot_de_passe* delpasswd(Mot_de_passe* psw, Mot_de_passe* first) {
    if (first == NULL || psw == NULL) {
        return first; // Rien à supprimer si la liste est vide ou si l'élément est NULL
    }

    // Cas où l'élément à supprimer est le premier élément de la liste
    if (first == psw) {
        Mot_de_passe* new_first = first->ptr; // Nouveau début de liste
        free(first);                          // Libération de l'élément
        return new_first;                     // Retourne le nouveau premier élément
    }

    // Recherche de l'élément avant celui à supprimer
    Mot_de_passe* search = first;
    while (search->ptr != psw && search->ptr != NULL) {
        search = search->ptr;
    }

    // Si l'élément est trouvé dans la liste
    if (search->ptr == psw) {
        search->ptr = psw->ptr;  // Contourner l'élément à supprimer
        free(psw);               // Libération de l'élément
    }

    return first;  // Retourne la tête de la liste, inchangée si `psw` n'était pas le premier
}

void modify_pswd(Mot_de_passe* mdp) {
    affiche_mdp(mdp);
    printf("\nQue voulez-vous modifier?\n1 : Login\n2 : Password\n3 : Site\n4 : Commentaire\n");
    
    int h;
    if (scanf(" %d", &h) != 1) {
        printf("Entrée non valide.\n");
        return;
    }

    switch (h) {
        case 1:
            printf("Entrez votre nouveau login (max 29 caractères) :\n");
            scanf("%29s", mdp->Login);
            break;
        case 2:
            printf("Entrez le nouveau password (max 29 caractères) :\n");
            scanf("%29s", mdp->Password);
            break;
        case 3:
            printf("Entrez le nouveau nom de site (max 49 caractères) :\n");
            scanf("%49s", mdp->Site);
            break;
        case 4:
            printf("Entrez le nouveau commentaire (max 255 caractères) :\n");
            scanf("%255s", mdp->Commentaire);
            break;
        default:
            printf("Option non valide.\n");
            return;
    }

    // Mise à jour de la date de modification
    if (time(&mdp->modif) == -1) {
        perror("Erreur lors de la mise à jour de la date de modification");
    }

    // Afficher les informations mises à jour
    affiche_mdp(mdp);
}