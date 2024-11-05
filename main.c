#include <stdio.h>
#include <stdlib.h>
#include "passfun.h"
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv[]) {

    FILE* fp = NULL;
    unsigned char pass[16];
    unsigned char buffer[16];
    unsigned char key[16];
    int dabet = 0;
    Mot_de_passe* scdptr;
    ij_vc* ivpointer = NULL;  // Initialisation à NULL pour éviter un double free potentiel
    FILE *fdecrypted;
    Mot_de_passe* first = NULL;
    FILE* fiv;

    // Vérification si le fichier crypted existe
    if (access("crypted", F_OK) == 0) {
        fp = fopen("crypted", "rb");
        fiv = fopen("IV", "rb");
        
        if (fp == NULL || fiv == NULL) {
            fprintf(stderr, "Erreur : impossible d'ouvrir les fichiers cryptés.\n");
            return 1;
        }
        
        printf("Bienvenue dans DR_Hash, entrez votre mot de passe pour continuer : ");
        scanf("%15s", pass); // Limite à 15 caractères

        ivpointer = get_cipher(fiv);
        if (ivpointer == NULL) {
            fprintf(stderr, "Erreur : IV non récupéré correctement.\n");
            fclose(fiv);
            return 1;
        }

        printf("IV récupéré : ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", ivpointer->IV[i]);
        }
        printf("\n");
        

        sha1_hash((const unsigned char *)pass, strlen((const char *)pass), key);
        printf("Clé SHA1 : ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");

        fdecrypted = fopen("decrypted", "wb");
        if (fdecrypted == NULL) {
            fprintf(stderr, "Erreur : impossible de créer le fichier décrypté.\n");
            fclose(fp);
            return 1;
        }

        aes_decrypt_file(fp, fdecrypted, key, ivpointer->IV);
        fclose(fdecrypted);
        fclose(fp);

        fdecrypted = fopen("decrypted", "rb");
        if (fdecrypted == NULL) {
            fprintf(stderr, "Erreur : impossible d'ouvrir le fichier décrypté pour lecture.\n");
            return 1;
        }
        
        first = recup_list(fdecrypted);
        
    }

    int loop = 1;
    int input;
    char slect;

    if (first != NULL) {
        dabet = first->ID + 1;
    }

    affiche_list(first);

    while (loop) {
        printf("menu:\n l pour lister toutes les entrées\n s pour sélectionner une entrée\n c pour créer une nouvelle entrée\n q pour quitter\n");
        scanf(" %c", &slect);

        switch (slect) {
            case 'l':
                affiche_list(first);
                break;

            case 's':
                printf("Entrez le numéro de l'entrée que vous souhaitez sélectionner : ");
                scanf("%d", &input);

                scdptr = select_mdp(first, input);
                affiche_mdp(scdptr);
                printf("Que voulez-vous faire ? d pour supprimer / m pour modifier\n");
                scanf(" %c", &slect);

                if (slect == 'd') {
                    first = delpasswd(scdptr, first);
                } else if (slect == 'm') {
                    modify_pswd(scdptr);
                }
                break;

            case 'c':
                dabet++;
                first = pass_query(dabet, first);
                break;

            case 'q':
                loop = 0;
                break;
        }
    }

    // Sauvegarde des données en clair
    fdecrypted = fopen("decrypted", "wb");
    if (fdecrypted == NULL) {
        fprintf(stderr, "Erreur : impossible d'ouvrir le fichier décrypté pour écriture.\n");
        liberer_mots_de_passe(first);
        if (ivpointer) free(ivpointer);
        return 1;
    }
    enregister(first, fdecrypted);

    // Chiffrement des données
    if (access("crypted", F_OK) != 0) {  // Si le fichier "crypted" n'existe pas encore
        printf("Entrez un mot de passe : ");
        scanf("%15s", pass);

        RAND_bytes(buffer, 16);
        ivpointer = (ij_vc*) malloc(sizeof(ij_vc));
        if (ivpointer == NULL) {
            fprintf(stderr, "Erreur d'allocation de mémoire pour ivpointer.\n");
            liberer_mots_de_passe(first);
            return 1;
        }
        
        sha1_hash((const unsigned char *)buffer, 16, ivpointer->IV);

        fiv = fopen("IV", "wb");
        if (fiv == NULL) {
            fprintf(stderr, "Erreur : impossible de créer le fichier IV.\n");
            free(ivpointer);
            liberer_mots_de_passe(first);
            return 1;
        }
        fwrite(ivpointer, sizeof(ij_vc), 1, fiv);
        fclose(fiv);

        sha1_hash((const unsigned char *)pass, strlen((const char *)pass), key);
        printf("IV récupéré : ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", ivpointer->IV[i]);
        }
        printf("\n");
        printf("Clé SHA1 : ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", key[i]);
        }
        printf("\n");
    }

    fp = fopen("crypted", "wb");
    fdecrypted = fopen("decrypted", "rb");
    if (fp == NULL || fdecrypted == NULL) {
        fprintf(stderr, "Erreur : impossible d'ouvrir les fichiers pour le chiffrement.\n");
        if (fp) fclose(fp);
        if (fdecrypted) fclose(fdecrypted);
        liberer_mots_de_passe(first);
        if (ivpointer) free(ivpointer);
        return 1;
    }
    aes_encrypt_file(fdecrypted, fp, key, ivpointer->IV);

    // Libération des ressources
    liberer_mots_de_passe(first);
    if (ivpointer) free(ivpointer);
    remove("decrypted");
    return 0;
}