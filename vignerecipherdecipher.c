/*
 * intmain.c
 *
 *  Created on: Feb 2013
 *      Author: Matteo Ruggero Ronchi
 *
 *  Copyright 2013 Matteo Ruggero Ronchi - matrronchi.license@gmail.com
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_SIZE 256
#define DIM_MAX_SOTTO_STR 15000	//dimensione massima di ogni sottostinga nel testo da cifrare
#define MAX_LUNGH_KEY 10	//lunghezza massima della chiave

//prototipi delle funzioni

void strippa(FILE *pf1, FILE *pf2);
void cifra(FILE *pf1, FILE *pf2, char *chiave);
double ic(FILE *pf1);
int freq(char *buffer, float freq[MAX_SIZE]);
int chiavefunc(int imax);
void decifra(FILE *pf1, FILE *pf2, char *chiave);

//main del programma

int main(int argc, char* argv[]){

	if(argc != 3 )
	{
		printf("\n\nTo execute program please use following instruction: \n - ./main [inputfile.txt] [your cryptographic key]\n\n");
		printf("Execution will result in the ciphering ([cifrato]) of [inputfile.txt] with the key [your cryptographic key] after having it cleared from punctation ([strippato])\n\n");
		exit(1);
	}

	if(strlen(argv[2]) > MAX_LUNGH_KEY )
	{
		printf("Please use a key no longer than 10 chars, %s is long %d \n\n", argv[2], strlen(argv[2]));
		exit(1);
	}
	
	FILE *pf1, *pf2, *pf3, *pfdc;
	double indc, icmax = 0.062;
	int num, dim, numcharr, i, j, k, imax, length, l;	
	static char *buffer, *chiavestr, *chiave, *puntarray[MAX_LUNGH_KEY];
	static float freqarray[MAX_SIZE], arric[MAX_SIZE];
	char chchiave, ch;
	static int buffertest[MAX_SIZE];	
	
	pf1 = fopen(argv[1], "r");
	pf2 = fopen("strippato", "w+");

	strippa(pf1, pf2);

	fclose(pf1);
	fclose(pf2);

	pf2 = fopen("strippato", "r");
	pf3 = fopen("cifrato", "w+");
	
	cifra(pf2, pf3, argv[2]);

	fclose(pf2);
	fclose(pf3);
	
	pf3 = fopen("cifrato", "r");

	indc = ic(pf3);

	printf("\n\nl'indice di coincidenza e' %f\n\n", indc);

//inizio routine per il calcolo della lunghezza della chiave

	if (pf3 != NULL){
 		fseek(pf3, 0, SEEK_END);
 		dim = ftell(pf3);
	}else{
		fprintf(stderr, "errore nell'apertura del file\n");
		return -1;
	}
	
	num = dim / sizeof(char);

	for(i = 1; i <= MAX_LUNGH_KEY; i++){
		
		numcharr = (int) (num / i) + 1;

		for (j = 0; j < num; j += i){
			fseek(pf3, j, SEEK_SET);
			ch = fgetc(pf3);
			buffertest[ch]++;
		}

		for(l = 0; l < MAX_SIZE; l++){
			if(buffertest[l] != 0){
				arric[i] += ((float) buffertest[l] / numcharr) * ((float) buffertest[l] / numcharr);
			}else{
				arric[i] += 0;
			}
		}
	
		for(k = 0; k < MAX_SIZE; k++)
			buffertest[k] = 0;
	}

	for(i = 1; i <= MAX_LUNGH_KEY; i++){
		if (arric[i] > icmax){			
			length = i;
			break;
		}
	}

//fine routine

//separazione del testo cifrato in sotto stringhe
		
	numcharr = (int) (num / length) + 1;

	buffer = calloc(numcharr, sizeof(char));

	for(i = 0; i < length; i++){
		k = 0;		
		for (j = i; j < num; j += length){
			fseek(pf3, j, SEEK_SET);
			buffer[k] = fgetc(pf3);
			k++;
		}

		puntarray[i] = malloc(strlen(buffer) + 1);
		
		strcpy(puntarray[i], buffer);
	}

	fclose(pf3);
		
//fine separazione
	
	chiave = calloc(length, sizeof(char));

	for(i = 0; i < length; i++){
		strcpy(buffer, puntarray[i]);
		imax = freq(buffer, freqarray);
		printf("\n");		
		chchiave = chiavefunc(imax);	
		printf("\nla lettera [%d] della chiave e' %c\n\n", i+1, chchiave);
		chiave[i] = chchiave;
	}

	pf3 = fopen("cifrato","r");

	pfdc = fopen("decifrato","w+");

	decifra(pf3, pfdc, chiave);

	fclose(pf3);
	
	fclose(pfdc);

	printf("Il risultato della decrittazione e' stato stampato sul file 'decifrato'\n");
}

//fine del main

/*funzione strippa
Prende come input il puntatore al file, in testo chiaro (lingua inglese), di cui si desidera effettuare la cifratura, e il puntatore al file 
su cui si desidera copiare il testo risultante dalla operazione di strippatura.

Questa funzione viene utilizzata per ripulire il testo da cifrare da tutta la punteggiatura ed i caratteri speciali. Cosi' da rendere in seguito possibile la cifratura utilizzando l'algoritmo di Vigenere. Stampa quindi il testo strippato sul file, puntato dal puntatore datole in ingresso.
*/
void strippa(FILE *pf1, FILE *pf2){

	int dim, num;
	unsigned char ch;
	
	if (pf1 != NULL){
		fseek(pf1, 0, SEEK_END);
 		dim = ftell(pf1);
	}else{
		fprintf(stderr, "errore nell'apertura del file\n");
	}

	for(num = 0; num < dim / sizeof(char); num++){
 		fseek(pf1, num, SEEK_SET);
 		ch = fgetc(pf1);
		if(ch <= 90 && ch >= 65)
   			fprintf(pf2, "%c", ch + 32);
   		else
			if(ch <= 122 && ch >= 97)
				fprintf(pf2, "%c", ch);
   			else
				;
		
	}
	
}

/*funzione cifra
Prende come input il puntatore al file, strippato mediante la funzione 'strippa', di cui si desidera effettuare la cifratura, il puntatore al file su cui si desidera copiare il testo risultante dalla operazione di cifratura, e la chiave mediante la quale bisogna implementare il metodo di Vigenere.

La funzione dopo aver generato la tabella di Vigenere, ne utilizza l'algoritmo per effettuare la trasposizione in codice. Consiste nella cifratura di ogni carattere nel testo con una diversa lettera della chiave, la quale viene poi ripetuta il numero necessario di volte affinche' tutto il testo risulti cifrato. Dunque stampa il risultato dell'algoritmo sul file, puntato dal puntatore passatole in ingresso.
*/
void cifra(FILE *pf1, FILE *pf2, char *chiave){

	FILE *pfap; //puntatore a un file (interno) di appoggio
	int i, j, dim, vigtable[26][26];
	unsigned char c, d, firstletter, chalpha;
	char * cc;//chiave cifratura
	
	for(i = 0, firstletter = 97; i < 26; i++, firstletter++){
		chalpha = firstletter;		
		for(j = 0; j < 26; j++){
			if(chalpha > 122)
				chalpha = 97;
			vigtable[i][j] = chalpha;
			chalpha++;
		}		
	}

	pfap = fopen("vigtable_cifra","w+");	
	
	//stampa, su file interno, della tabella di vigenere

	for(i = 0; i < 26; i++){
		for(j = 0; j < 26; j++){
			fprintf(pfap,"[%c]", vigtable[i][j]);
		}
	fprintf(pfap,"\n");
	}

	fclose(pfap);
	
	//fine procedeura di stampa	

	if (pf1 != NULL)
		;
	else
		fprintf(stderr, "errore nell'apertura del file in lettura\n");
		
	if((cc = chiave) && *cc != '\0'){		
			fseek(pf1, 0, SEEK_END);
 			dim = ftell(pf1);
			if(pf2 != NULL){				
				for(i = 0; i < dim; i++){
					fseek(pf1, i, SEEK_SET);					
					c = getc(pf1); 					
					if(!*cc) cc = chiave;
					d = vigtable[c - 97][*(cc++) - 97];				
					fprintf(pf2, "%c", d);
				}		
			}else
				fprintf(stderr, "errore nell'apertura del file in scrittura\n");
	}else
		fprintf(stderr, "\nerrore nella decifrazione del file\nimpossibile ottenere la chiave di cifratura\n");

}

/*funzione indice di coincidenza
Questa funzione prende in ingresso il puntatore al file cifrato e restituisce il valore (in doppia precisione) dell'indice di coincidenza relativo al testo.
*/
double ic(FILE *pf1){

	FILE *pfap; //puntatore a un file (interno) di appoggio
	static int array[MAX_SIZE];
	int dim, num, i;
	char ch;
	double ic = 0;

	pfap = fopen("IC","w");
	
	if(pf1 != NULL){
		fseek(pf1, 0, SEEK_END);
		dim = ftell(pf1);
		fprintf(pfap, "\nla dimensione del file e' %d bytes\n", dim);
		fprintf(pfap, "\nla dimensione di un char e' %d byte\n", sizeof(char));
		fprintf(pfap, "\nil numero di caratteri nel file e' %d\n\n", dim / sizeof(char));
	}else{
		fprintf(stderr, "\nErrore nell'apertura del file\n");
		return -1;
	}

	for(num = 0; num < dim / sizeof(char); num++){
		fseek(pf1, num, SEEK_SET);
		ch = fgetc(pf1);
		array[ch]++;
	}

	num = dim / sizeof(char);

	for(i = 0; i < MAX_SIZE; i++){
		if(array[i] != 0){
			ic += ((float) array[i] / num) * ((float) array[i] / num);
		}else{
			ic += 0;
		}
	}
	
	fprintf(pfap, "\nl'indice di coincidenza e' %f \n", ic);
		
	fclose(pfap);
	
	return ic;	
}

/*funzione freq
La funzione prende come input un puntatore a caratteri (buffer) sul quale sono stati copiati temporaneamente tutti i caratteri di una delle sottostringe del testo cifrato, e un array di float sul quale memorizza le frequenze relative alla sottostringa data in ingresso. 

La routine studia la frequenza con cui si ripetono i caratteri presenti nella sottostringa in esame e ne memorizza il piu' frequente, del quale viene restituito il valore ascii corrispondente.
*/
int freq(char *buffer, float freq[MAX_SIZE]){
	
	static int array[MAX_SIZE];
	int num, i, imax = 0, ch, numcharr;
	float maxfreq = 0;
	
	numcharr = strlen(buffer);

	for(num = 0; num < numcharr; num++){
 		ch = buffer[num];
//printf("[DEBUG] - numcharr %d - num %d - ch %c / %d \n", numcharr, num, ch, ch);
 		array[ch]++;
	}

	for(i = 0; i < MAX_SIZE; i++){	
		if (array[i] != 0){			
			freq[i] = ((float) array[i] / numcharr)*100; 			
			printf("la frequenza di '%c - %d' nel testo e' == %.3f \n", i, i, freq[i]);
			if (freq[i] > maxfreq){			
				maxfreq = freq[i];
				imax = i;
			}
 		}else
 			;  
	}

	for(i = 0; i < MAX_SIZE; i++)
		array[i] = 0;

	return imax;
}
/*funzione chiavefunc
L'input e' costituito dal valore ascii del carattere piu' frequente della sottostringa presa in esame dalla funzione precedente.

Supponendo che nel testo chiaro (in lingua inglese) questo corrisponda alla lettera 'e' la funzione ricava mediante la tabella di Vigenere la lettera con la	quale la 'e' debba essere stata cifrata per ottenere il carattere imax. Questa e' dunque una delle lettere costituente la chiave e rappresenta l'output della funzione.
*/
int chiavefunc(int imax){

	FILE *pfap; //puntatore a un file (interno) di appoggio
	int i, j, firstletter, chalpha, vigtable[26][26];
	unsigned char d;
	char * cc;//chiave cifratura
	
	for(i = 0, firstletter = 97; i < 26; i++, firstletter++){
		chalpha = firstletter;		
		for(j = 0; j < 26; j++){
			if(chalpha > 122)
				chalpha = 97;
			vigtable[i][j] = chalpha;
			chalpha++;
		}		
	}

	pfap = fopen("vigtable_chiavefunc","w+");	
	
	for(i = 0; i < 26; i++){
		for(j = 0; j < 26; j++){
			fprintf(pfap, "[%c]", vigtable[i][j]);
		}
	fprintf(pfap, "\n");
	}

	fclose(pfap);
	
	for(i = 0; i < 26; i++){
		if(vigtable[4][i] != imax)
			;
		else
			break;
	}
	
	d = i + 97;

return d;
}

/*funzione decifra
Prende come input il puntatore al file cifrato, il puntatore al file su cui si desidera scrivere il testo decrittato mediante la routine della funzione, e la chiave di cifratura ricavata dalla esecuzione delle precedenti parti del programma, mediante la quale bisognerà implementare la decrittatura.

La funzione si appoggia alla tabella di Vigenere, ed esegue un confronto fra ogni singolo carettere del testo cifrato e l'elemento della tabella con indice di colonna la lettera corrispondente alla chiave di cifratura (ricavata) e di riga una variabile contatore. Quando il confronto da esito positivo il carattere corrispondente all' indice di riga viene scritto sul file decrittato (puntato dal puntatore a file passato come argomento); la routine e' ripetuta finche' tutti il testo cifrato e' stato scorso.
*/
void decifra(FILE *pf1, FILE *pf2, char *chiave){

	FILE *pfap; //puntatore a un file (interno) di appoggio
	int i, j, firstletter, chalpha, vigtable[26][26], dim;
	unsigned char c, d;
	char * cc;//chiave cifratura
		
	printf("\nla chiave di cifratura e' ''%s''\n", chiave);

	for(i = 0, firstletter = 97; i < 26; i++, firstletter++){
		chalpha = firstletter;		
		for(j = 0; j < 26; j++){
			if(chalpha > 122)
				chalpha = 97;
			vigtable[i][j] = chalpha;
			chalpha++;
		}		
	}

	pfap = fopen("vigtable_decifra","w+");	
	
	for(i = 0; i < 26; i++){
		for(j = 0; j < 26; j++){
			fprintf(pfap,"[%c]", vigtable[i][j]);
		}
	fprintf(pfap, "\n");
	}

	fclose(pfap);

	
	if (pf1 != NULL)
		;
	else
		fprintf(stderr,"errore nell'apertura del file\n");
	
	if((cc = chiave) && *cc != '\0'){		
	
		fseek(pf1, 0, SEEK_END);
 		dim = ftell(pf1);
					
		if(pf2 != NULL){				
			for(i = 0; i < dim; i++){
				fseek(pf1, i, SEEK_SET);					
				c = getc(pf1); 					
				if(!*cc) cc = chiave;
					for(j = 0; j < 26; j++){					
						if(c == vigtable[j][(*cc) - 97]){	
							d = j + 97;
							fprintf(pf2, "%c", d);
						}else
							;				
					}
					*(cc++);
			}		
		}else
			fprintf(stderr, "errore nell'apertura del file in scrittura\n");
	}else
		fprintf(stderr, "\nerrore nella decifrazione del file\nimpossibile ottenere la chiave di cifratura\n");
}

//fine progetto
