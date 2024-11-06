#include <stdio.h>    // pour FILE
#include <stddef.h> 
#include <time.h>
#define AES_BLOCK_SIZE 16
typedef struct mdp Mot_de_passe;

typedef struct mdp{
    int ID;
    char Login[30];
    char Password[30];
    char Site[50];
    char Commentaire[256];
    long int creation;
    long int modif;
    Mot_de_passe* ptr;
} Mot_de_passe;


typedef struct cipher {
	unsigned char IV[16];
} ij_vc;

void show_password(Mot_de_passe* ps);
void affiche_list(Mot_de_passe* mdp);
void liberer_mots_de_passe(Mot_de_passe* liste);
ij_vc* get_cipher(FILE* fp);
Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin);
Mot_de_passe* recup_list(FILE* fiel);
void sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output);
void affiche_mdp(Mot_de_passe* mdp);
Mot_de_passe* select_mdp(Mot_de_passe* hea, int idex);
Mot_de_passe* delpasswd(Mot_de_passe* psw, Mot_de_passe* first);
void modify_pswd(Mot_de_passe* mdp);
void enregister(Mot_de_passe* mdp, FILE* file);
int aes_decrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv);
int aes_encrypt_file(FILE *ifp, FILE *ofp, const unsigned char *key, const unsigned char *iv);
