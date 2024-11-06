#include "passfun.h"
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

void copy_to_clipboard(const char *arr) {//fonction pour copier le mot de passe dans le presse papier
    char command[1024];
    //on regarde quel os parce que les commandes diffèrent en fonction
    //attention j'ai pas testé pour windows et mac
    #if defined(_WIN32) || defined(_WIN64)
        if (OpenClipboard(NULL)) {
        
        EmptyClipboard();

        // Créer une handle de mémoire globale
        size_t len = strlen(arr) + 1;
        HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, len);
        
        if (hGlobal) {
            // Verrouiller la mémoire pour obtenir un pointeur
            char *ptr = (char *)GlobalLock(hGlobal);
            
            // Copier la chaîne dans la mémoire
            memcpy(ptr, arr, len);

            // Déverrouiller la mémoire
            GlobalUnlock(hGlobal);

            // Placer la chaîne dans le presse-papiers
            SetClipboardData(CF_TEXT, hGlobal);
        }

       
        CloseClipboard();
    } else {
        printf("Erreur lors de l'ouverture du presse-papiers.\n");
    }

    #elif defined(__APPLE__) || defined(__MACH__)
        rsnprintf(command, sizeof(command), "echo \"%s\" | pbcopy", arr);
        system(command);

    #elif defined(__linux__)
        // Vérification si c'est WSL en lisant le fichier /proc/version
        FILE* file = fopen("/proc/version", "r");
        if (file) {
            char buffer[256];
            fread(buffer, sizeof(char), sizeof(buffer) - 1, file);
            fclose(file);
            buffer[255] = '\0';
            if (strstr(buffer, "Microsoft") || strstr(buffer, "WSL")) {
                snprintf(command, sizeof(command), "echo \"%s\" | clip.exe", arr);
                system(command);
            } else {//sinon c'est linux normal
                snprintf(command, sizeof(command), "echo \"%s\" | xclip -selection clipboard", arr);
                system(command);
            }
        } else {
            snprintf(command, sizeof(command), "echo \"%s\" | xclip -selection clipboard", arr);
            system(command);
        }
    #endif
}

Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin) {//fonction pour demander a l'utilisateur de creer un mot de passe
    char t;
    printf("Voulez vous génerer un mot de passe aléatoire? y/n\n");
    scanf(" %c", &t);
    int rand = 0;
    if(t =='y'){
        rand = 1;
    }
    Mot_de_passe* ptr = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));//création de la struct
    if (ptr == NULL) {
        perror("Erreur d'allocation de mémoire");
        return NULL;
    }

    // Sécurisation des saisies
    printf("Site : ");
    scanf("%49s", ptr->Site);  
    
    printf("Login : ");
    scanf("%29s", ptr->Login);
    if(!rand){
        printf("Mot de passe : ");
        scanf("%29s", ptr->Password);
    }
    else{//si l'utilisateur a choisi l'option random password
        random_passwd(ptr);
    }
    
    printf("Commentaires : ");
    scanf("%255s", ptr->Commentaire);

    ptr->ptr = ancin;
    ptr->ID = ID;

    time_t cre;  

    time(&cre); 

    
    struct tm* local_time = localtime(&cre);

    //trnasformation des dates en string parce que en time_t ça marche pas quand on veut changer uniqueemtn la date de modif jsp pourquoi
    strftime(ptr->creation, sizeof(ptr->creation), "%d/%m/%Y %H:%M:%S", local_time);
    strftime(ptr->modif, sizeof(ptr->modif), "%d/%m/%Y %H:%M:%S", local_time);

    return ptr;
}


void sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output) {//fonction pour hasher en sha1
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

ij_vc* get_cipher(FILE* fp) {//prendre l'iv dans le fichier 
    // allocation d un nouvel objet ij_vc
    ij_vc* new_node = (ij_vc*)malloc(sizeof(ij_vc));
    if (new_node == NULL) {
        perror("Memory allocation failed");
        return NULL; 
    }

    // Lecture dans new_node
    if (fread(new_node, sizeof(ij_vc), 1, fp) != 1) {
        perror("Failed to read structure from file");
        free(new_node);  
        return NULL;
    }
    fclose(fp);
    return new_node;  
}


void free_mots_de_passe(Mot_de_passe* liste) {//pour free la linked list a la fon du programme
    Mot_de_passe* courant;
    while (liste != NULL) {//parcourt la linked list et les free un par un
        courant = liste;
        liste = liste->ptr;
        free(courant);
    }
}

void affiche_mdp(Mot_de_passe* mdp) {//affiche un structure mot de pase
    if (mdp == NULL) {
        fprintf(stderr, "Erreur le pointeur vers Mot_de_passe est NULL.\n");
        return;
    }

    // Affichage direct des valeurs de time_t pour le débogage
    //printf("Valeur brute de la date de création: %ld\n", mdp->creation);
    //printf("Valeur brute de la date de modification: %ld\n", mdp->modif);

    // Affichage des informations du mot de passe
    printf("Entrée %d :\ndate d'ajout : %s\ndate de modif : %s\nsite : %s\nlogin : %s\ncommentaires : %s\n",
           mdp->ID, mdp->creation, mdp->modif, mdp->Site,mdp->Login, mdp->Commentaire);
    
}

void save_list_to_csv(Mot_de_passe* head, const char* filename) {//pour dump les mots de passe dans un csv
    // Ouvrir le fichier en mode écriture
    FILE* file = fopen(filename, "w");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return;
    }

    // Parcourir la liste et écrire chaque élément dans le fichier
    Mot_de_passe* current = head;
    while (current != NULL) {
        
        fprintf(file, "%d,%s,%s,%s,%s,%s,%s\n",
                current->ID,
                current->Login,
                current->Password,
                current->Site,
                current->Commentaire,
                current->creation,
                current->modif);
        
        
        current = current->ptr;
    }

    fclose(file);
    printf("Liste sauvegardée dans %s\n", filename);
}

void affiche_list(Mot_de_passe* mdp){//affiche list sert a afficher la liste de tous le mdp
	Mot_de_passe* tmp = mdp;
	while (tmp != NULL)
	{
		affiche_mdp(tmp);//on appalle affiche_mdp pour chaque mdp de la linked list
		tmp = tmp->ptr;
	}
	
}

Mot_de_passe* select_mdp(Mot_de_passe* hea, int idex){//permet de selectionner un mdp par son ID
    Mot_de_passe* head =hea;
	while (head != NULL && head->ID != idex){//tant que index n'est pas le bon on continue
        head = head->ptr;
    }
    return head;
}

Mot_de_passe* select_mdp_ask(Mot_de_passe* hea){//permet de retourner un element mdp grace au nom du site
    Mot_de_passe* head =hea;
    printf("\nentrez le site pour lequel vous souhaitez prendre le mot de passe\n");
    char entre[50];
    scanf("%s", entre);
	while (head != NULL && strcmp(head->Site, entre)){//tant que le nom du site n'est pas le bon on continue
        head = head->ptr;
    }
    return head;
}

Mot_de_passe* select_mdp_ask_login(Mot_de_passe* hea){//retourne un pointeur vers l'objet mot de passe possédant le login demandé
    Mot_de_passe* head =hea;
    printf("\nentrez le login pour lequel vous souhaitez prendre le mot de passe\n");
    char entre[50];
    scanf("%s", entre);
	while (head != NULL && strcmp(head->Login, entre)){//tant que le login n'est pas le bon on continue
        head = head->ptr;
    }
    return head;
}

//I WILL TREAT HER BETTER THTAN YOU EVER WILL JUSTE YOU WATCH

Mot_de_passe* recup_list(FILE* fiel) {//recupérer la liste des mots de passe dan sle fichier
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

        //printf("Récupération ID: %d, Site: %s\n", new_node->ID, new_node->Site);

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


void enregister(Mot_de_passe* mdp, FILE* file) {//enregisteer la liste dans le fichier
    Mot_de_passe* ptr1 = mdp;
    while (ptr1 != NULL) {
        printf("Enregistrement ID: %d, Site: %s\n", ptr1->ID, ptr1->Site);//enregistre chaque element jusqu'au dernier
        fwrite(ptr1, sizeof(Mot_de_passe), 1, file);
        ptr1 = ptr1->ptr;
    }
    fclose(file);
}


Mot_de_passe* delpasswd(Mot_de_passe* psw, Mot_de_passe* first) {//pour delete le mdp
    /*if (first == NULL || psw == NULL) {
        return first; // rien r supprimer si la liste est vide ou si l'élément est null
    }*/

    // si c'est le premier element de la liste
    if (first == psw) {
        Mot_de_passe* new_first = first->ptr; 
        free(first);                          
        return new_first;                     
    }

    // cherche l'élément avant celui à supprimer
    Mot_de_passe* search = first;
    while (search->ptr != psw && search->ptr != NULL) {
        search = search->ptr;
    }

    if (search->ptr == psw) {
        search->ptr = psw->ptr;  // raccorder les deux mots de passe adjascents
        free(psw);               
    }

    return first; 
}

void modify_pswd(Mot_de_passe* mdp) {//fonction pour modifier le mdp
    affiche_mdp(mdp);
    printf("\nQue voulez-vous modifier?\n1 : Login\n2 : Password\n3 : Site\n4 : Commentaire\n5 : définir un mot de pase aléatoire\n");
    
    int h;
    if (scanf(" %d", &h) != 1) {
        printf("Entrée non valide.\n");
        return;
    }

    switch (h) {
        case 1:
            printf("Entrez votre nouveau login :\n");
            scanf("%29s", mdp->Login);
            break;
        case 2:
            printf("Entrez le nouveau password :\n");
            scanf("%29s", mdp->Password);
            break;
        case 3:
            printf("Entrez le nouveau nom de site :\n");
            scanf("%49s", mdp->Site);
            break;
        case 4:
            printf("Entrez le nouveau commentaire :\n");
            scanf("%255s", mdp->Commentaire);
            break;
        case 5:
            random_passwd(mdp);
            break;
        default:
            printf("Option non valide\n");
            return;
    }

    // Mise à jour de la date de modification 
    time_t cre;  

    time(&cre);  

    struct tm* local_time = localtime(&cre);
    strftime(mdp->modif, sizeof(mdp->modif), "%d/%m/%Y %H:%M:%S", local_time);
    affiche_mdp(mdp);
}


int aes_decrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv) {//decrypte un fichier en utilisant l'aes128
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len;
    size_t cipherlen;
    unsigned char *ciphertext, *plaintext;
    //dérivé de la methode vue en cours mais pour un fichier
    // obtenir la taille du fichier d'entrée
    fseek(ifp, 0L, SEEK_END);
    cipherlen = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    ciphertext = malloc(cipherlen);
    plaintext = malloc(cipherlen); 

    if (ciphertext == NULL || plaintext == NULL) {
        printf("Erreur d'allocation de mémoire\n");
        return -1;
    }

    // lire le fichier chiffré
    if (fread(ciphertext, 1, cipherlen, ifp) != cipherlen) {
        printf("Erreur lors de la lecture du fichier chiffré\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Initialisation du contexte
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Erreur lors de l'initialisation du contexte AES\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Initialisation de la décryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1) {
        printf("Erreur lors de l'initialisation de la décryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // Déchiffrement des données
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipherlen) != 1) {
        printf("Erreur lors de la décryption\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    plaintext_len = len;

    // finalisation de la décryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        printf("Erreur lors de la finalisation de la décryption.\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    plaintext_len += len;

    // écrire les données déchiffrées
    if (fwrite(plaintext, 1, plaintext_len, ofp) != plaintext_len) { 
        printf("Erreur lors de l'écriture des données déchiffrées\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    printf("Déchiffrement réussi, taille des données déchiffrées : %zu octets\n", plaintext_len);

    // nettoyage
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    free(plaintext);

    return plaintext_len;
}

int aes_encrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv) {//fonction pour chiffrere des données dans un fichir
    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len;  
    size_t cipherlen;
    unsigned char *plaintext, *ciphertext;
    //similaire a celle vue en cours
    // Obtenir la taille du fichier d'entrée
    fseek(ifp, 0L, SEEK_END);
    plaintext_len = ftell(ifp);
    fseek(ifp, 0L, SEEK_SET);

    plaintext = malloc(plaintext_len);
    ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);

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

    // Initialisation de l'encryption
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

    // Ecrire les données chiffrées dans le fichier de sortie
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

    return cipherlen; 
}

// Fonction pour charger les mots de passe depuis un fichier CSV
void load_from_csv(Mot_de_passe** head, const char* filename) {
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Erreur lors de l'ouverture du fichier");
        return;
    }

    char line[512];
    int max_id = find_max(*head); // Trouver le plus grand ID dans la liste
   
    while (fgets(line, sizeof(line), file)) {
        // allocation d'un nouvel objet mot de passe
        Mot_de_passe* new_node = (Mot_de_passe*)malloc(sizeof(Mot_de_passe));
        if (new_node == NULL) {
            perror("Erreur d'allocation de mémoire");
            fclose(file);
            return;
        }

        // lire les champs du CSV
        
        sscanf(line, "%d,%29[^,],%29[^,],%49[^,],%255[^,],%19[^,],%19[^\n]",
               &new_node->ID, new_node->Login, new_node->Password, new_node->Site, 
               new_node->Commentaire, new_node->creation, new_node->modif);

        // vérifier si l'ID importé est inférieur à max_id
        if (new_node->ID <= max_id) {
            max_id ++;
            new_node->ID = max_id;  // si l'ID est inférieur ou égal à max_id, on le met à jour
        }
       
        new_node->ptr = NULL;

        // ajouter le nouveau mot de passe à la liste
        if (*head == NULL) {
            *head = new_node; 
        } else {
            Mot_de_passe* temp = *head;
            while (temp->ptr != NULL) {
                temp = temp->ptr;
            }
            temp->ptr = new_node;// ajout du nouvel element à la fin de la liste
        }

        // Mettre à jour max_id pour la prochaine itération
        max_id = find_max(*head);
        //il se peut que ça skip des valeurs mais l'interet de ID c'est juste qu'il soit unique pas forcément que ça soit dans l'ordre numérique
    }

    fclose(file);
}

int find_max(Mot_de_passe* head) {//fonction pour trouver le plus grand ID pour etre sur qu'il n'y pas de doublons
    int max_id = 0; //initialise a 0
    Mot_de_passe* current = head;

    // Parcourt la liste pour trouver le plus grand ID
    while (current != NULL) {
        if (current->ID > max_id) {
            max_id = current->ID;
        }
        current = current->ptr;
    }

    return max_id;
}

void random_passwd(Mot_de_passe* mdp) {//fonction qui set un password aléatoire
    int l;
    printf("Select the length of your pass (min 12): ");
    scanf("%d", &l);
    if (l < 12) {
        l = 12;
    }
    if(l>28){
        l=28;
    }

    int c;
    const char allowed[] = "azertyuiopqsdfghjklmwxcvbn?.!§^1234567890)=àç_è-(é&ù~@]}{[|#²AZERTYUIOPMLKJHGFDSQWXCVBN*µ<>";//chaine des caractères a utiliser

    srand(time(NULL));

    for (int i = 0; i < l; i++) {
        c = rand() % strlen(allowed);//construction de mot de passe
        mdp->Password[i] = allowed[c];  
    }
    mdp->Password[l] = '\0';  
}