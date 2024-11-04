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
    if (access("crypted", F_OK)){//si ce n'est pas la premiere fois que le programme est lancé le file crypted existe
        fp = fopen("crypted", "rb");
        FILE* fiv = fopen("IV","rb");
        printf("welcome to DR_Hash, enter your passowrd to continue : ");
        scanf("%s", pass);
        ivpointer = get_cipher(fiv);
        sha1_hash((unsigned char *)pass, strlen(pass), key);
        fdecrypted = fopen("decrypted", "wb");
        decrypt(fp,fdecrypted,key, ivpointer);
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
        printf("menu :\n l to list all entries\n s to select an entry\n c to create a new entry\n");
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
                    
                }
                else if(slect == 'm'){

                }
                //TODO le reste
            case 'c':
                dabet ++;
                first = pass_query(dabet,first);
                break;
            
        }
    }
    
}