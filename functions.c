#include "passfun.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>


Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin) {
    printf("Pour quel site est ce mot de passe ?\n");
    Mot_de_passe* ptr = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
    if (ptr == NULL) {
        perror("Erreur d'allocation de mémoire");
        return NULL;
    }

    // Sécurisation des saisies
    printf("Site : ");
    scanf("%49s", ptr->Site);  // Limite à 49 caractères pour laisser place au '\0'
    
    printf("Login : ");
    scanf("%29s", ptr->Login);
    
    printf("Mot de passe : ");
    scanf("%29s", ptr->Password);
    
    printf("Commentaires : ");
    scanf("%255s", ptr->Commentaire);

    ptr->ptr = ancin;
    ptr->ID = ID;

    time(&ptr->creation);
    time(&ptr->modif);

    return ptr;
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

    // Affichage direct des valeurs de time_t pour le débogage
    printf("Valeur brute de la date de création: %ld\n", mdp->creation);
    printf("Valeur brute de la date de modification: %ld\n", mdp->modif);

    // Conversion de la date de création
    struct tm* local_time = localtime(&mdp->creation);
    char* date_str = (char*)malloc(100 * sizeof(char)); 
     if (date_str == NULL) {
        perror("Erreur d'allocation de mémoire");
        return;
    }
    struct tm* local_time2 = localtime(&mdp->modif);
    char* date_str2 = (char*)malloc(100 * sizeof(char)); 
    if (date_str2 == NULL) {
        perror("Erreur d'allocation de mémoire");
        return;
    }
    strftime(date_str, 100, "%d/%m/%Y %H:%M:%S", local_time);
    strftime(date_str2, 100, "%d/%m/%Y %H:%M:%S", local_time2);

    // Affichage des informations du mot de passe
    printf("Entrée %d :\ndate d'ajout : %s\ndate de modif : %s\nsite : %s\nlogin : %s\ncommentaires : %s\n",
           mdp->ID, date_str, date_str2, mdp->Site, mdp->Login, mdp->Commentaire);
    free(date_str);
    free(date_str2);
}

void copy_to_clipboard(Mot_de_passe* md){
    char command[1024];
    snprintf(command, sizeof(command), "echo \"%s\" | clip.exe", md->Password);
    system(command);
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
    Mot_de_passe* new_node;

    while (1) {
        new_node = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
        if (new_node == NULL) {
            perror("Memory allocation failed");
            fclose(fiel);
            return head;  
        }
        if (fread(new_node, sizeof(Mot_de_passe), 1, fiel) != 1) {
            free(new_node);  
            break; // Exit if no more entries to read
        }
        new_node->ptr = NULL;  

        printf("Récupération ID: %d, Site: %s\n", new_node->ID, new_node->Site);

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



void enregister(Mot_de_passe* mdp, FILE* file) {
    Mot_de_passe* ptr1 = mdp;
    while (ptr1 != NULL) {
        printf("Enregistrement ID: %d, Site: %s\n", ptr1->ID, ptr1->Site);
        fwrite(ptr1, sizeof(Mot_de_passe), 1, file);
        ptr1 = ptr1->ptr;
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

    // Mise à jour de la date de modification uniquement
    time(&mdp->modif);

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
