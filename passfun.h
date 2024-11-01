typedef struct mdp{
    int ID;
    char Login[30];
    char Password[30];
    char Site[50];
    char Commentaire[256];
    int creation;
    int modif;
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

void pass_cypher(Mot_de_passe* ptr);
void pass_decypher(Mot_de_passe* ptr);
Mot_de_passe* pass_modify(Mot_de_passe* ptr);
void pass_delete(Mot_de_passe* ptr);
Mot_de_passe* pass_search();
int aes_encrypt (const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
int aes_decrypt (const unsigned char *ciphertext, int cipherlen, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
void sha1_hash(const char *input, unsigned int inputlen, unsigned char *output, unsigned int *output_length);
int hex_to_bin(const char* hex_string, unsigned char* bin_output);
void encrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]);
void decrypt(FILE *ifp, FILE *ofp, unsigned char key[], unsigned char iv[]);