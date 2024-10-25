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

Mot_de_passe* pass_query(int ID);

void pass_cypher(Mot_de_passe* ptr);
void pass_decypher(Mot_de_passe* ptr);
Mot_de_passe* pass_modify(Mot_de_passe* ptr);
void pass_delete(Mot_de_passe* ptr);
Mot_de_passe* pass_search();
void main_menu();