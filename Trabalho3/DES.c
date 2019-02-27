/*Author: Rui Pedro Paiva
Teoria da Informação, LEI, 2008/2009*/

#include "DES.h"

/*função para encriptação*/
int DES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 0);
}


/*função para decriptação*/
int unDES (char* inFileName, unsigned long long key)
{
	return DESgeneral(inFileName, key, 1);
}


/*função geral para encriptação (type = 0) e decriptação (type = 1) de um ficheiro */
int DESgeneral (char* inFileName, unsigned long long key, int type)
{
	FILE* DESInFile;
	unsigned char* inByteArray;
	long inFileSize;
	unsigned char* crpByteArray;
	char* outFileName;
	int write;
	char response;
	struct stat stFileInfo;
	FILE* DESOutFile;
	char suf[5];


	/*abrir ficheiro e ler tamanho*/
	DESInFile = fopen(inFileName, "rb");
	if (DESInFile == NULL)
	{
		printf("Error opening file for reading. Exiting...\n");
		return 1;
	}
	fseek(DESInFile, 0L, SEEK_END);
	inFileSize = ftell(DESInFile);  /*ignore EOF*/
	fseek(DESInFile, 0L, SEEK_SET);

	/*ler ficheiro inteiro para array inByteArray	*/
	inByteArray = (unsigned char*) calloc(inFileSize, sizeof(unsigned char));
	fread(inByteArray, 1, inFileSize, DESInFile);


	/*encriptar dados e assinatura no array*/
	crpByteArray = encryptDES(inByteArray, inFileSize, key, type);

	/*flush do crpByteArray para ficheiro*/
	/*nome do ficheiro de saída*/
	if (type == 0)  /*encriptação*/
	{
		outFileName = (char*) calloc(strlen(inFileName) + 5, sizeof(char));
		strcpy(outFileName, inFileName);
		strcat(outFileName, ".DES");
	}
	else  /*decriptação*/
	{
		strcpy(suf, &inFileName[strlen(inFileName) - 4]);
		if (strcmp(suf, ".DES") == 0)
		{
			outFileName = (char*) calloc(strlen(inFileName) + 5, sizeof(char));
			strcpy(outFileName, "DES_");
			strcat(outFileName, inFileName);
			outFileName[strlen(outFileName) - 4] = 0;
		}
		else
		{
			outFileName = (char*) calloc(14, sizeof(char));
			strcpy(outFileName, "DES_decrypted");
		}

	}


	/*verificar assinatura*/
	if (type == 1)
	{
		/******* ADICIONAR CîDIGO:

		 implementar  funo:
		 int checkSignature(unsigned char* inByteArray, unsigned char* hash)  // ver abaixo
		 e retirar hash aos dados
		 abortar desencriptao caso a verificao da assinatura no passe no teste
		 ***********************/
	}

	/*criar ficheiro*/
	write = 1;
	if(stat(outFileName, &stFileInfo) == 0) /*see if file already exists*/
	{
		printf ("File already exists. Overwrite (y/n)?: ");
		response = getchar();
		if (response == 'n')
			write = 0;
		printf("\n");
		fflush(stdin);
	}

	if (write)
	{
		DESOutFile = fopen(outFileName, "wb");
		if (DESOutFile == NULL)
		{
			printf("Error opening file for writing!!! Exiting...\n");
			return -1;
		}
		fwrite(crpByteArray, 1, inFileSize, DESOutFile);
		fclose(DESOutFile);
	}

	/*finalizações*/
	free(inByteArray);
	free(outFileName);
	free(crpByteArray);
	fclose(DESInFile);

	return 0;
}


/* função para encriptação/decriptação de dados no array inByteArray, de dimensão dim*/
unsigned char* encryptDES(unsigned char* inByteArray, long dim, unsigned long long key, int type)
{
	unsigned long long subKeys[16];
	unsigned char* outByteArray;
	unsigned long long plain, cipher, inv;
	int i, j;

	/*obtém sub-keys (16 de comprimento 48)*/
	/**** ADICIONAR CÓDIGO PARA A FUNÇÃO DESKEYSCHEDULE (ABAIXO) ********/
	DESKeySchedule(key, subKeys);



	if (type == 1) /*decrypt --> inverter subKeys*/
	{
		for(i=0;i<8;i++){
			inv=subKeys[i];
			subKeys[i] = subKeys[15-i];
			subKeys[15-i]=inv;
		}

	}

	outByteArray = (unsigned char*) calloc(dim, sizeof(unsigned char));
	i = 0;
	plain = 0;
	while (i < dim)
	{
		plain = 0;
		j = i;
		while (j < i + 8 && j < dim)
		{
 			plain = plain | ((unsigned long long)inByteArray[j] << (64 - 8*(j-i+1)));
			j++;
		}
		/*determina cifra*/
		if (j - i == 8)  /*ficheiro é múltiplo de 8 bytes*/
			/**** ADICIONAR CÓDIGO PARA A FUNÇÃO ENCRYPTDESPLAIN (ABAIXO) ********/
			cipher = encryptDESplain(plain, subKeys);
		else
			cipher = plain;


		/*guarda cifra no array de saída*/
		j = i;
		while (j < i + 8 && j < dim)
		{
			outByteArray[j] = (unsigned char) (cipher >> (56 - 8*(j-i)) & (0xFF));
			j++;
		}

		i = j;
	}

	return outByteArray;
}


/************************************************************************************/
/***************************** ADICIONAR CóDIGO *************************************/
/************************************************************************************/


/* função para encriptação de uma mensagem de 64 bits (plain), com base nas subKeys*/
/*devolve a mensagem cifrada*/
unsigned long long encryptDESplain(unsigned long long plain, unsigned long long* subKeys)
{
    printf("Plain: %#llx",plain);

	int ip[] = {58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9,  1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

	int ipInv[] = {40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6 ,46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25};

	int e[] = {32, 1,  2,  3,  4,  5, 4,  5,  6,  7,  8,  9, 8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};

	int p[] = {16, 7,  20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10, 2,  8,  24, 14, 32, 27, 3,  9, 19, 13, 30, 6, 22, 11, 4,  25};
	unsigned int aux2;
	unsigned long long aux,plainPermu=0,eR, l, r, rAntigo,swaper,permu2=0;
	int i,j;

	/* faz a permutacao IP*/
	for (i=0;i<64;i++){
		aux = (plain<<(ip[i]-1));
		aux >>= 63;
		plainPermu <<= 1;
		plainPermu |= aux;
	}
	    printf("Permutacao IP: %#llx\n",plainPermu);

	/* insere o l0 e r0*/
	l = (plainPermu>>32);
	r = (plainPermu<<32);
	r >>= 32;

	printf("L0: %#x\n",l);
	printf("R0: %#x\n",r);

	for(i = 0; i < 16; i++){
		rAntigo = r;


		/* F */
		/*Permuta R com E*/

		eR = 0;
        for(j=0;j<48;j++){
            aux2 = (r << (e[j] - 1));
            aux2 >>= 31;

            eR <<= 1;
            eR |= aux2;

        }
        printf("T: %#llx\n", eR);

        /*XOR com a sub Key*/
        eR ^= subKeys[i];

        printf("T': %#llx\n",eR);

        /* S */
        eR = sBox(eR);
        printf("T'': %#llx\n",eR);
        /* Permutacao P */
        r = 0;
        for(j=0;j<32;j++){
            aux2 = (eR << (p[j] - 1));
            aux2 >>= 31;

            r <<= 1;
            r |= aux2;
        }
        printf("T''': %#llx\n",r);

        r ^= l;
        l = rAntigo;
    }

    /*swaper = (r<<32) | l;*/
    swaper = r;
	swaper <<= 32;
	swaper |= l;
    printf("Swaper: %#llx\n",swaper);

    for (i=0;i<64;i++){
        aux = (swaper<<(ipInv[i]-1));
        aux >>= 63;
        permu2 <<= 1;
        permu2 |= aux;
    }
    printf("Codificado: %#llx\n",permu2);
	return permu2;
}

unsigned long sBox(unsigned long long eR){

	int S1[4][16]={{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8}, {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}};

	int S2[4][16]={{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10}, {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5}, {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15}, {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}};

	int S3[4][16]={{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8}, {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1}, {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7}, {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}};

	int S4[4][16]={{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15}, {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9}, {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4}, {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}};

	int S5[4][16]= {{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9}, {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6}, {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14}, {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}};

	int S6[4][16]={{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11}, {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8}, {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6}, {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}};

	int S7[4][16]={{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1}, {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6}, {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2}, {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}};

	int S8[4][16]={{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7}, {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2}, {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8}, {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

	unsigned long final = 0;
	int aux[8],i,x,y;


    for(i=0;i<8;i++){
        aux[i] = (eR>>((7-i)*6)) & ((unsigned long long)pow(2,6)-1);
        printf("B%d: %#x\n",i,aux[i]);
    }

	x = ((aux[0]>>5)<<1) + (aux[0]&1)	;
	y = (aux[0]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S1[x][y];

	x = ((aux[1]>>5)<<1) + (aux[1]&1);
	y = (aux[1]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S2[x][y];

	x = ((aux[2]>>5)<<1) + (aux[2]&1);
	y = (aux[2]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S3[x][y];

	x = ((aux[3]>>5)<<1) + (aux[3]&1);
	y = (aux[3]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S4[x][y];

	x = ((aux[4]>>5)<<1) + (aux[4]&1);
	y = (aux[4]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S5[x][y];

	x = ((aux[5]>>5)<<1) + (aux[5]&1);
	y = (aux[5]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S6[x][y];

	x = ((aux[6]>>5)<<1) + (aux[6]&1);
	y = (aux[6]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S7[x][y];

	x = ((aux[7]>>5)<<1) + (aux[7]&1);
	y = (aux[7]>>1) & (int)(pow(2,4)-1);
	final = (final<<4) + S8[x][y];
	return final;
}

/* função para gerar sub-keys (uma chave para cada uma das 16 iterações)*/
void DESKeySchedule(unsigned long long key, unsigned long long* subKeys)
{
	int pc1[] = {57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};
	int pc2[] = {14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
	int leftShift[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	unsigned long long keyPermu1 = 0,keyPermu2 = 0, aux;
	unsigned int c[17], d[17];
	int i, j;

    printf("Key: 0x%#llx\n",key);

	/* faz a permutacao PC-1*/
	for (i=0;i<56;i++){
		aux = (key<<(pc1[i]-1));
		aux >>= 63;
		keyPermu1 <<= 1;
		keyPermu1 |= aux;
	}
	printf("Permutação pc1: %#llx\n",keyPermu1);

	/* insere o C0 e o D0*/
	c[0] = (keyPermu1 >> 28);
	aux = (keyPermu1 <<28);
	d[0] = (aux >> 28);

    printf("C0: %x\n",c[0]);
    printf("D0: %x\n",d[0]);

	/* insere os outros C e D*/
for(i=1;i<=16;i++) {

    aux = c[i-1]>>(28-leftShift[i-1]);
    c[i] = ((c[i-1]<<(leftShift[i-1]))+aux) & (long)pow(2,28)-1;
    aux = d[i-1]>>(28-leftShift[i-1]);
    d[i] = ((d[i-1]<<(leftShift[i-1]))+aux) & (long)pow(2,28)-1;
    printf("C%d: %x\n",i,c[i]);
    printf("D%d: %x\n",i,d[i]);
}

	/* insere as subKeys*/
	for(i=0;i<16;i++)
	{
		keyPermu2 = 0;
		subKeys[i] = c[i+1];
		subKeys[i] <<= 28;
		subKeys[i] |= (d[i+1]);
		/* faz a PC-2*/
		for(j=0;j<48;j++)
		{
			aux = (subKeys[i] << (8 + pc2[j] -1));
			aux >>= 63;
			keyPermu2 <<= 1;
			keyPermu2 |= aux;
		}
		subKeys[i] = keyPermu2;

		printf("subKey%d: %llx\n",i+1,subKeys[i]);
	}
}
