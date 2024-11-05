#include <stdio.h>
#include <stdlib.h>
#include "passfun.h"
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    (void) argc; // Supprime les avertissements pour les paramètres non utilisés
    (void) argv;

    FILE* fp = NULL;
    unsigned char pass[16];
    unsigned char buffer[16];
    unsigned char key[16];
    int dabet = 0;
    Mot_de_passe* scdptr;
    ij_vc* ivpointer;
    FILE *fdecrypted;
    Mot_de_passe* first = NULL;
    FILE* fiv;

    if (access("crypted", F_OK) == 0) {  // Vérifie si le fichier "crypted" existe
        fp = fopen("crypted", "rb");
        fiv = fopen("IV", "rb");
        printf("welcome to DR_Hash, enter your password to continue: ");
        scanf("%15s", pass); // Limite l'entrée à 15 caractères pour éviter les dépassements de buffer

        ivpointer = get_cipher(fiv);
        sha1_hash((const unsigned char *)pass, strlen((const char *)pass), key);

        fdecrypted = fopen("decrypted", "wb");
        decrypt(fp, fdecrypted, key, ivpointer->IV);
        fclose(fdecrypted);
        fclose(fp);
        fclose(fiv);

        fdecrypted = fopen("decrypted", "rb");
        first = recup_list(fdecrypted);
        fclose(fdecrypted);
    }

    int loop = 1;
    int input;
    char slect;
    if (first != NULL) {
        dabet = first->ID + 1;
    }
    affiche_mdp(first);

    while (loop) {
        printf("menu:\n l to list all entries\n s to select an entry\n c to create a new entry\n q to quit\n");
        scanf(" %c", &slect);

        switch (slect) {
            case 'l':
                affiche_mdp(first);
                break;

            case 's':
                printf("Enter the number of the entry you want to select: ");
                scanf("%d", &input); // Utilise &input pour passer l'adresse
                scdptr = select_mdp(first, input);

                printf("What would you like to do? d to delete / m to modify\n");
                scanf(" %c", &slect);

                if (slect == 'd') {
                    first = delpasswd(scdptr, first);
                } else if (slect == 'm') {
                    modify_pswd(scdptr);
                }
                break; // Ajout de `break` pour éviter la chute

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
    enregister(first, fdecrypted);
    fclose(fdecrypted);

    // Chiffrement des données
    if (access("crypted", F_OK) != 0) {  // Si le fichier "crypted" n'existe pas encore
        printf("Enter a password: ");
        scanf("%15s", pass);  // Limite à 15 caractères

        RAND_bytes(buffer, 16);
        ivpointer = (ij_vc*) malloc(sizeof(ij_vc));
        sha1_hash((const unsigned char *)buffer, 16, ivpointer->IV);

        fiv = fopen("IV", "wb");
        fwrite(ivpointer, sizeof(ij_vc), 1, fiv);
        fclose(fiv); // Écrit l'IV dans un fichier

        sha1_hash((const unsigned char *)pass, strlen((const char *)pass), key);
    }

    fp = fopen("crypted", "wb");
    fdecrypted = fopen("decrypted", "rb");
    encrypt(fdecrypted, fp, key, ivpointer->IV);

    fclose(fp);
    fclose(fdecrypted);
    free(ivpointer); // Libère la mémoire allouée pour ivpointer
}
