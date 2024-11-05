#include <stdio.h>    // pour FILE
#include <stddef.h> 
#include <time.h>

typedef struct mdp Mot_de_passe;

typedef struct mdp{
    int ID;
    char Login[30];
    char Password[30];
    char Site[50];
    char Commentaire[256];
    time_t creation;
    time_t modif;
    Mot_de_passe* ptr;
} Mot_de_passe;

typedef struct AEScipher {
	unsigned char IV[16];
	unsigned char key[16];
} AEScipher;

typedef struct cipher {
	unsigned char IV[16];
} ij_vc;

ij_vc* get_cipher(FILE* fp);
Mot_de_passe* pass_query(int ID, Mot_de_passe* ancin);
Mot_de_passe* recup_list(FILE* fiel);
void pass_delete(Mot_de_passe* ptr);
int aes_encrypt (const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
int aes_decrypt (const unsigned char *ciphertext, int cipherlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
void sha1_hash(const unsigned char *input, size_t input_len, unsigned char *output);
int hex_to_bin(const char* hex_string, unsigned char* bin_output);
void encrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]);
void decrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]);
void affiche_mdp(Mot_de_passe* mdp);
Mot_de_passe* select_mdp(Mot_de_passe* hea, int idex);
Mot_de_passe* delpasswd(Mot_de_passe* psw, Mot_de_passe* first);
void modify_pswd(Mot_de_passe* mdp);
void enregister(Mot_de_passe* mdp, FILE* file);
