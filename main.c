#include <stdio.h>
#include <stdlib.h>
#include "passfun.h"
#include <openssl/evp.h>
#include <string.h>
#include <openssl/rand.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char* argv){
    FILE* fp = NULL;
    unsigned char pass[16];
    unsigned char buffer[16];
    unsigned char key[16];
    int dabet = 0;
    Mot_de_passe* scdptr;
    ij_vc* ivpointer;
    FILE * fdecrypted;
    Mot_de_passe* first = NULL;
    FILE* fiv;
    if (access("crypted", F_OK)){//si ce n'est pas la premiere fois que le programme est lancé le file crypted existe
        fp = fopen("crypted", "rb");
        fiv = fopen("IV","rb");
        printf("welcome to DR_Hash, enter your passowrd to continue : ");
        scanf("%s", pass);
        ivpointer = get_cipher(fiv);
        sha1_hash((unsigned char *)pass, strlen(pass), key);
        fdecrypted = fopen("decrypted", "wb");
        decrypt(fp,fdecrypted,key, ivpointer->IV);
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
    if(first != NULL){
        dabet = first->ID +1;
    }
    affiche_mdp(first);
    while(loop){
        printf("menu :\n l to list all entries\n s to select an entry\n c to create a new entry\nq to quit\n");
        scanf(" %c", &slect);
        switch(slect){
            case 'l':
                affiche_mdp(first);
                break;
            case 's':
                printf("enter the number of th enty you want to select\n");
                scanf(" %d", input);
                scdptr = select_mdp(first,input);
                printf("que voulez vous faire? d to delete / m to modify\n");
                scanf(" %c", &slect);
                if(slect == 'd'){
                    first = delpasswd(scdptr, first);
                }
                else if(slect == 'm'){
                    modify_pswd(scdptr);
                }
            case 'c':
                dabet ++;
                first = pass_query(dabet,first);
                break;
            case 'q':
                loop = 0;
                break;
            
        }
    }
    //dabord write les données dans un fichier normal
    fdecrypted = fopen("decrypted", "rb");
    enregister(first, fdecrypted);
    fclose(fdecrypted);
    //chiffrer les données
    if (!access("crypted", F_OK)){// si yavait pas un fichier avant donc ça veut dire yavait pas encore de mdp
        printf("entrez un mot de passe\n");
        scanf("%s", pass);
        RAND_bytes(buffer, 16);
        ivpointer = (ij_vc*)malloc(sizeof(ij_vc));
        sha1_hash((unsigned char *)buffer, 16, ivpointer->IV);
        fiv = fopen("IV", 'wb');
        fwrite(ivpointer, sizeof(ij_vc), 1, fiv);
        fclose(fiv);
    }
    
    
}