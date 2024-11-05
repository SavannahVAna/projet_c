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
    size_t fsize = ftell(ifp);  // Changer 'int' en 'size_t'
    // Remettre le pointeur de fichier au début
    fseek(ifp, 0L, SEEK_SET);

    size_t outLen1 = 0, outLen2 = 0;  // Changer 'int' en 'size_t'
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize + AES_BLOCK_SIZE); // Prendre en compte le rembourrage potentiel

    // Lire le fichier
    size_t bytesRead = fread(indata, sizeof(char), fsize, ifp); // Utiliser size_t pour bytesRead
    if (bytesRead != fsize) {
        fprintf(stderr, "Erreur lors de la lecture du fichier d'entrée.\n");
        free(indata);
        free(outdata);
        return;
    }

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
    if (EVP_EncryptUpdate(ctx, outdata, (int*)&outLen1, indata, (int)fsize) != 1) {  // Cast explicite ici
        fprintf(stderr, "Erreur lors du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    if (EVP_EncryptFinal_ex(ctx, outdata + outLen1, (int*)&outLen2) != 1) {  // Cast explicite ici
        fprintf(stderr, "Erreur lors de la finalisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
        free(indata);
        free(outdata);
        return;
    }

    // Écrire le résultat dans le fichier de sortie
    size_t bytesWritten = fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp); // Utiliser size_t pour bytesWritten
    if (bytesWritten != outLen1 + outLen2) {
        fprintf(stderr, "Erreur lors de l'écriture des données dans le fichier de sortie.\n");
        free(indata);
        free(outdata);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx); // Libérer le contexte
    free(indata);
    free(outdata);
}



void decrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]) {
    fseek(ifp, 0L, SEEK_END);
    size_t fsize = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    if (fsize <= 0) {
        fprintf(stderr, "Taille de fichier invalide.\n");
        return;
    }

    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);

    if (indata == NULL || outdata == NULL) {
        fprintf(stderr, "Erreur d'allocation de mémoire.\n");
        free(indata);
        free(outdata);
        return;
    }

    size_t bytesRead = fread(indata, sizeof(char), fsize, ifp);  // Lire le fichier chiffré
    if (bytesRead != fsize) {
        fprintf(stderr, "Erreur lors de la lecture du fichier chiffré.\n");
        free(indata);
        free(outdata);
        return;
    }

    // Afficher les données lues pour vérifier leur contenu
    printf("Données lues du fichier chiffré : ");
    for (size_t i = 0; i < bytesRead; i++) {
        printf("%02x", indata[i]);
    }
    printf("\n");

    // Vérifiez si la clé et l'IV sont corrects (loggez-les pour vérifier)
    printf("Clé utilisée : ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    printf("IV utilisé : ");
    for (size_t i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Erreur lors de l'allocation du contexte de déchiffrement.\n");
        free(indata);
        free(outdata);
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Erreur lors de l'initialisation du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(indata);
        free(outdata);
        return;
    }

    int outLen1 = 0, outLen2 = 0;
    if (EVP_DecryptUpdate(ctx, outdata, &outLen1, indata, (int)bytesRead) != 1) {
        fprintf(stderr, "Erreur lors du déchiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(indata);
        free(outdata);
        return;
    }

    // Finalisation du déchiffrement
    if (EVP_DecryptFinal_ex(ctx, outdata + outLen1, &outLen2) != 1) {
        fprintf(stderr, "Erreur lors de la finalisation du déchiffrement. Vérifiez la clé ou le fichier crypté.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(indata);
        free(outdata);
        return;
    }

    // Écrire les données décryptées dans le fichier de sortie
    size_t bytesWritten = fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp);
    if (bytesWritten != (size_t)(outLen1 + outLen2)) {
        fprintf(stderr, "Erreur lors de l'écriture des données dans le fichier de sortie.\n");
    }

    printf("Déchiffrement réussi, taille des données déchiffrées : %d\n", outLen1 + outLen2);

    // Libération de la mémoire
    EVP_CIPHER_CTX_free(ctx);
    free(indata);
    free(outdata);
}



void liberer_mots_de_passe(Mot_de_passe* liste) {
    Mot_de_passe* courant;
    while (liste != NULL) {
        courant = liste;
        liste = liste->ptr;
        free(courant);
    }
}

void affiche_mdp(Mot_de_passe* mdp) {
    if (mdp == NULL) {
        fprintf(stderr, "Erreur : Le pointeur vers Mot_de_passe est NULL.\n");
        return;
    }
    
    // Récupération des temps de création et de modification
    struct tm* local_time = localtime(&mdp->creation);
    if (local_time == NULL) {
        fprintf(stderr, "Erreur lors de la conversion de time_t en struct tm.\n");
        return;
    }

    char date_str[100]; 
    struct tm* local_time2 = localtime(&mdp->modif);
    if (local_time2 == NULL) {
        fprintf(stderr, "Erreur lors de la conversion de time_t en struct tm.\n");
        return;
    }

    // Formatage des dates
    strftime(date_str, sizeof(date_str), "%d/%m/%Y %H:%M:%S", local_time);
    char date_str2[100]; 
    strftime(date_str2, sizeof(date_str2), "%d/%m/%Y %H:%M:%S", local_time2);

    // Affichage des informations du mot de passe
    printf("Entrée %d :\ndate d'ajout : %s\ndate de modif : %s\nsite : %s\nlogin : %s\ncommentaires : %s\n",
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
  
    Mot_de_passe* ptr1 = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
    if (ptr1 == NULL) {
        perror("Erreur d'allocation de mémoire");
        return NULL;
    }
    
    char e[] = "errroorrroror";
    strncpy(ptr1->Site, e, sizeof(ptr1->Site) - 1); // Copie la chaîne dans Site, en s'assurant de ne pas dépasser la taille
    ptr1->Site[sizeof(ptr1->Site) - 1] = '\0'; // Ajouter un '\0' à la fin au cas où la chaîne serait trop longue
    
    strncpy(ptr1->Login, e, sizeof(ptr1->Login) - 1); 
    ptr1->Login[sizeof(ptr1->Login) - 1] = '\0'; 
   
    strncpy(ptr1->Password, e, sizeof(ptr1->Password) - 1); 
    ptr1->Password[sizeof(ptr1->Password) - 1] = '\0'; 
    strncpy(ptr1->Commentaire, e, sizeof(ptr1->Commentaire) - 1); 
    ptr1->Commentaire[sizeof(ptr1->Commentaire) - 1] = '\0'; 
    ptr1->ptr = mdp;
    ptr1->ID = mdp->ID +1;
    time(&ptr1->creation);
    time(&ptr1->modif);

    Mot_de_passe* ptr0 = ptr1 ->ptr;
    while(ptr0 != NULL){
        fwrite(ptr0, sizeof(Mot_de_passe), 1, file);
        ptr0 = ptr0->ptr;
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
            printf("Entrez votre nouveau login  :\n");
            scanf("%29s", mdp->Login);
            break;
        case 2:
            printf("Entrez le nouveau password  :\n");
            scanf("%29s", mdp->Password);
            break;
        case 3:
            printf("Entrez le nouveau nom de site  :\n");
            scanf("%49s", mdp->Site);
            break;
        case 4:
            printf("Entrez le nouveau commentaire  :\n");
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

int aes_decrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len;  // Changement ici, passer à size_t
    size_t cipherlen;
    unsigned char *ciphertext, *plaintext;

    // Obtenir la taille du fichier d'entrée
    fseek(ifp, 0L, SEEK_END);
    cipherlen = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    // Allocation de mémoire pour les données chiffrées et déchiffrées
    ciphertext = malloc(cipherlen);
    plaintext = malloc(cipherlen);  // Prévoir la même taille, voire plus en cas de padding

    if (ciphertext == NULL || plaintext == NULL) {
        printf("Erreur d'allocation de mémoire.\n");
        return -1;
    }

    // Lire le fichier chiffré
    if (fread(ciphertext, 1, cipherlen, ifp) != cipherlen) {
        printf("Erreur lors de la lecture du fichier chiffré.\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Initialisation du contexte de déchiffrement
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Erreur lors de l'initialisation du contexte AES.\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Initialisation de la décryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        printf("Erreur lors de l'initialisation de la décryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Déchiffrement des données
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen) != 1) {
        printf("Erreur lors de la décryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    plaintext_len = len;

    // Finalisation de la décryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        printf("Erreur lors de la finalisation de la décryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    plaintext_len += len;

    // Écrire les données déchiffrées dans le fichier de sortie
    if (fwrite(plaintext, 1, plaintext_len, ofp) != plaintext_len) {  // Pas de warning maintenant
        printf("Erreur lors de l'écriture des données déchiffrées dans le fichier de sortie.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    printf("Déchiffrement réussi, taille des données déchiffrées : %zu octets\n", plaintext_len);  // Utilisation de %zu pour size_t

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);

    return plaintext_len;  // Retourner la taille des données déchiffrées
}

int aes_encrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len;  // Utilisation de size_t pour la taille du texte en clair
    size_t cipherlen;
    unsigned char *plaintext, *ciphertext;

    // Obtenir la taille du fichier d'entrée
    fseek(ifp, 0L, SEEK_END);
    plaintext_len = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    // Allocation de mémoire pour les données en clair et chiffrées
    plaintext = malloc(plaintext_len);
    ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);  // Taille pour supporter padding

    if (plaintext == NULL || ciphertext == NULL) {
        printf("Erreur d'allocation de mémoire.\n");
        return -1;
    }

    // Lire le fichier en clair
    if (fread(plaintext, 1, plaintext_len, ifp) != plaintext_len) {
        printf("Erreur lors de la lecture du fichier en clair.\n");
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    // Initialisation du contexte de chiffrement
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Erreur lors de l'initialisation du contexte AES.\n");
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    // Initialisation de la encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        printf("Erreur lors de l'initialisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    // Chiffrement des données
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        printf("Erreur lors du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    cipherlen = len;

    // Finalisation du chiffrement
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("Erreur lors de la finalisation du chiffrement.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    cipherlen += len;

    // Écrire les données chiffrées dans le fichier de sortie
    if (fwrite(ciphertext, 1, cipherlen, ofp) != cipherlen) {
        printf("Erreur lors de l'écriture des données chiffrées dans le fichier de sortie.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    printf("Chiffrement réussi, taille des données chiffrées : %zu octets\n", cipherlen);

    // Nettoyage
    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);

    return cipherlen;  // Retourner la taille des données chiffrées
}
