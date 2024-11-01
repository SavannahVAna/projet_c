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
    char pass[20];
    if (access("crypted", F_OK)){
        fp = fopen("crypted", "rb");
        FILE* fiv = fopen("IV","rb");
        printf("welcome to DR_Hash, enter your passowrd to continue : ");
        scanf("%s", pass);
    }
}