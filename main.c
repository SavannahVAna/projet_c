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
    ij_vc* ivpointer = NULL;  // Initialisation des diverses variables utilisées
    FILE *fdecrypted;
    Mot_de_passe* first = NULL;
    FILE* fiv;

    // Vérification si le fichier crypted existe
    //si il existe ça veut dire il y a deja des données sauvegardées sinon skip ça (premiere utilisation)
    if (access("crypted", F_OK) == 0) {
        fp = fopen("crypted", "rb");
        fiv = fopen("IV", "rb");
        
        if (fp == NULL || fiv == NULL) {
            fprintf(stderr, "Erreur : impossible d'ouvrir les fichiers cryptés.\n");
            return 1;
        }
        
        printf("Bienvenue dans DR_Hash, entrez votre mot de passe pour continuer : ");
        scanf("%15s", pass); // Limite à 15 caractères

        ivpointer = get_cipher(fiv);//recuperer l'iv dans le fichier IV et l'écrir dans la struct iv_jc
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
        
        //sha1 du password pour avoir la clé
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
        //ouverture et déchiffrement du ficher
        //il l'écrit dans le ficher fdecrypted
        aes_decrypt_file(fp, fdecrypted, key, ivpointer->IV);
        fclose(fdecrypted);
        fclose(fp);
        //lecture du fichier decrypted pour sortir les mdp
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
    char namefile[20];
    
    dabet = find_max(first);
    affiche_list(first);

    while (loop) {
        printf("menu:\n l pour lister toutes les entrées\n s pour sélectionner une entrée a l'aide de son index, p pour le faire a partir du nom du site, n a partir du login\n c pour créer une nouvelle entrée\n e pour exporter les mots de passe en csv, i pour en importer\n q pour quitter\n");
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
                if(scdptr !=NULL){
                    printf("Que voulez-vous faire ? d pour supprimer / m pour modifier / h to copy password\n");
                    scanf(" %c", &slect);

                    if (slect == 'd') {
                        first = delpasswd(scdptr, first);
                    } else if (slect == 'm') {
                        modify_pswd(scdptr);
                    }
                    else if (slect == 'h')
                    {
                        copy_to_clipboard(scdptr->Password);
                    }
                    
                }
                else
                {
                    printf("aucune corresondace\n");
                }
                
                break;
            case 'p':

                scdptr = select_mdp_ask(first);
                affiche_mdp(scdptr);
                if(scdptr != NULL){
                    printf("Que voulez-vous faire ? d pour supprimer / m pour modifier / h to copy password\n");
                    scanf(" %c", &slect);

                    if (slect == 'd') {
                        first = delpasswd(scdptr, first);
                    } else if (slect == 'm') {
                        modify_pswd(scdptr);
                    }
                    else if (slect == 'h')
                    {
                        copy_to_clipboard(scdptr->Password);
                    }
                    
                }
                else{
                    printf("aucune corresondace\n");
                }
                break;
            case 'n':

                scdptr = select_mdp_ask_login(first);
                affiche_mdp(scdptr);
                if(scdptr != NULL){
                    printf("Que voulez-vous faire ? d pour supprimer / m pour modifier / h to copy password\n");
                    scanf(" %c", &slect);

                    if (slect == 'd') {
                        first = delpasswd(scdptr, first);
                    } else if (slect == 'm') {
                        modify_pswd(scdptr);
                    }
                    else if (slect == 'h')
                    {
                        copy_to_clipboard(scdptr->Password);
                    }
                    
                }
                else{
                    printf("aucune corresondace\n");
                }
                break;
            case 'c':
                dabet++;
                first = pass_query(dabet, first);
                break;
            case 'e':
                save_list_to_csv(first, "export.csv");
                break;
            
            case 'i':
                printf("enter the name of the file you wish to import ");
                scanf("%s", namefile);
                
                load_from_csv(&first, namefile);
              
                dabet = find_max(first);
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
        free_mots_de_passe(first);
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
            free_mots_de_passe(first);
            return 1;
        }
        
        sha1_hash((const unsigned char *)buffer, 16, ivpointer->IV);

        fiv = fopen("IV", "wb");
        if (fiv == NULL) {
            fprintf(stderr, "Erreur : impossible de créer le fichier IV.\n");
            free(ivpointer);
            free_mots_de_passe(first);
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
    //chiffrement
    fp = fopen("crypted", "wb");
    fdecrypted = fopen("decrypted", "rb");
    if (fp == NULL || fdecrypted == NULL) {
        fprintf(stderr, "Erreur : impossible d'ouvrir les fichiers pour le chiffrement.\n");
        if (fp) fclose(fp);
        if (fdecrypted) fclose(fdecrypted);
        free_mots_de_passe(first);
        if (ivpointer) free(ivpointer);
        return 1;
    }
    aes_encrypt_file(fdecrypted, fp, key, ivpointer->IV);

    // Libération des ressources
    free_mots_de_passe(first);
    if (ivpointer) free(ivpointer);
    //delete decrypted pou rqu'il ne reste plus que le fichier chiffré
    remove("decrypted");
    return 0;
}