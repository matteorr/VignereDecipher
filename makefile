all:vignere

vignere:vignerecipherdecipher.o
	gcc vignerecipherdecipher.o -o vignere

vignerecipherdecipher.o:vignerecipherdecipher.c
	gcc -c vignerecipherdecipher.c          

clean:
	rm -rf *o vignere strippato cifrato vigtable_* IC
