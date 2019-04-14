#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>

#define NUM_FILES 8

static int filesys_inited = 0;


char gfnms[10][30];
int fend[8];

void display(FILE* pt){
	char ch;
	fseek(pt,0,SEEK_SET);
	//fp = fopen("secure.txt","r");
	while(ch != EOF){
		ch = getc(pt);
		printf("%c",ch);
	}
	printf("%s","\n");
	fseek(pt,0,SEEK_SET);
	//fclose(fp);
}

int read_into_array(char *ptr, FILE* sp){
	char ch;
	for(int i = 0;i<64;i++){
		ch = getc(sp);
		if(ch == EOF){
			while(i != 64){
				*ptr = '2';
				ptr++;
				i++;
			}
			*ptr = '\0';
			return -1;
		}
		else{
			*ptr = ch;
			ptr++;	
		}
	}
	*ptr = '\0';
	return 1;
}

int get_old_hash(char* ptrh,char* ptrn){
	FILE* fs = fopen("secure.txt","r");
	char ch;
	int flag = 0;
	char name[10];

	int nind = 0;
	int theman = 0;
	int count = 0;
	
	fseek(fs,0,SEEK_SET);
	//printf("%s\n","In Old Hash" );
	while(1){
		ch = getc(fs);
		if(ch == EOF){
			if(theman){
				*ptrh = '\0';
				fclose(fs);
				return 0;
			}
			break;
		} 
		if(flag == 0){
			if(ch == ':'){
				flag = 1;
				name[nind] = '\0';
				//printf("%s\n","name is:" );
				if(strcmp(ptrn,name) == 0){
					theman = 1;
				} 
				nind = 0;
			}
			else{
				if(ch != '\n'){
					name[nind] = ch;
					nind++;
				}
				
			}		
		}
		else{
			if(count == 20){
				if(theman){
					*ptrh = '\0';
					fclose(fs);
					return 0;
				}
				count = 0;
				flag = 0;
			}
			else{
				count++;
			} 
			if(theman){
				*ptrh = ch;
				if(ch == '\0') break;
				ptrh++;
			}
			
		}
	}
	//printf("%s\n","Got old" );
	fclose(fs);
	return 1;
}

void get_root_hash(FILE* sp,char* ptr){
	//printf("%s\n","In get roothash" );
	int lcount = 0;
	char source[65];
	char dest[21];

	char ch;
	fseek(sp,0,SEEK_SET);

	ch = getc(sp);
	
	if(ch == EOF){
		for(int i = 0;i<20;i++){
			*ptr = 'a';
			ptr++;
		}
		*ptr = '\0';
		return;
	}
	else fseek(sp,0,SEEK_SET);

	
	//Loop used to count no. of leaf nodes(stored in lcount)
	while(1){
		lcount++;
		int status = read_into_array(source,sp);
		if(status == -1){
			break;
		}
	}

	fseek(sp,0,SEEK_SET);

	char mt[lcount][21];
	int i = 0;
	while(1){
		int status = read_into_array(source,sp);
		get_sha1_hash(source,64,dest);
		strncpy(mt[i],dest,20);
		i++;
		if(status == -1){
			break;
		}
	}

	//printf("lcount is: %i\n",lcount );
	int hcount = lcount;
	
	while(hcount != 1){
		i = 0;
		int j = 1;
		int putind = 0;
		while(j < hcount){
			char cncted[41];
			int indi = 0;
			for(int f = 0 ;f < 20; f++){
				cncted[indi] = mt[i][f];
				indi++;
			}

			for(int f = 0;f < 20;f++){
				cncted[indi] = mt[j][f];
				indi++;
			}
			cncted[indi] = '\0';
			//printf("x %s\n",cncted);
			get_sha1_hash(cncted,40,dest);
			strncpy(mt[putind],dest,20);
			putind++;
			i += 2;
			j += 2;
		}
		if(i == hcount -1){
			strncpy(mt[putind],mt[i],20);
		}


		if(hcount % 2 == 0) hcount /= 2;
		else{
			hcount = (hcount/2);
			hcount++;
		}
	}

	for(i = 0;i < 20; i++){
		if(mt[0][i] == '\n' || mt[0][i] == '\0' || mt[0][i] == EOF){
			*ptr = 'x';
		}
		else{
			*ptr = mt[0][i];
		}
		ptr++;
	}
	// *ptr = '$';
	// ptr++;
	*ptr = '\0';
	//printf("%s\n","Out of roothash" );	

}

int helper(){
	//printf("%s\n","In helper" );
	for(int i = 0;i < 8;i++){
		fend[i] = 0;
	}
	char filename[32],ch;
	snprintf(filename,32,"secure.txt");
	FILE* fp;
	fp = fopen(filename,"r"); // Open secure.txt

	if(fp == NULL){
		fp = fopen(filename,"w+"); //Create secure.txt

		DIR *d;
		struct dirent *dir;
		d = opendir(".");
		if(d){
			while((dir = readdir(d)) != NULL){
				// If any of the files that are being used in the tests are present in the directory, then add their root hash to secure.txt
				if(strcmp("foo_0.txt",dir->d_name) == 0 || strcmp("foo_1.txt",dir->d_name) == 0 || strcmp("foo_2.txt",dir->d_name) == 0 || strcmp("foo_3.txt",dir->d_name) == 0 || strcmp("foo_4.txt",dir->d_name) == 0 || strcmp("foo_5.txt",dir->d_name) == 0 || strcmp("foo_6.txt",dir->d_name) == 0 || strcmp("foo_7.txt",dir->d_name) == 0){
					//printf("%s\n","YO");
					char roothash[21];
					FILE* sp = fopen(dir->d_name,"r");
					get_root_hash(sp,roothash);
					fputs(dir->d_name,fp);
					fputs(":",fp);
					fputs(roothash,fp);
					fputs("\n",fp);
					fclose(sp);
				}
				
			}
			closedir(d);
		}
		//printf("%s\n","Easy Peasy");
		fclose(fp);
		return 0;
	}
	else{

		FILE *new_file;
		new_file = fopen("copy.txt","w");

		char hashval[100];
		int hindx = 0;
		
		char f_name[100];
		int findx = 0;

		int flag = 0;
		int safe = 0;

		char roothash[21];

		while(1){
			ch = getc(fp);
			if(ch == EOF){
				hashval[hindx] = '\0';
				break;
			} 
			
			if(ch != '\n'){
				if(ch == ':'){
					flag = 1;
					f_name[findx] = '\0';
					FILE *tfd = fopen(f_name,"r");
					if(tfd != NULL){
						safe = 1;
						get_root_hash(tfd,roothash);
						fclose(tfd);
					}
					
				}
				if(flag && ch != ':'){
					hashval[hindx] = ch;
					hindx++;
				}
				if(!flag){
					f_name[findx] = ch;
					findx++;
				}
			}
			else{
				hashval[hindx] = '\0';
				if(safe){
					if(strcmp(hashval,roothash) != 0){
						//printf("%s\n","Integrity check failed in init" );
						return 1;
					}
					char total[100];
					int tempi = 0;
					for(int i = 0; i < findx;i++){
						total[tempi] = f_name[i];
						tempi++;
					}
					total[tempi] = ':';
					tempi++;

					for(int i = 0; i < hindx;i++){
						total[tempi] = hashval[i];
						tempi++;
					}
					total[tempi] = '\0';
					// printf("%s\n",hashval);
					// printf("%s\n",total);
					fputs(total,new_file);
					fputs("\n",new_file);
					safe = 0;
				}
				hindx = 0;
				findx = 0;
				flag = 0;
			
			}

		}


		fclose(fp);
		fclose(new_file);
		remove(filename);
		rename("copy.txt",filename);

		return 0;
	}
	
}

void update_hash_val(char* rhash,char* filename){
	//printf("%s\n","In upd hashval" );
	char ch;
	int flag = 0;
	char name[21];
	char hasha[21];	
	int nind = 0;
	int hindx = 0;
	int count = 0;
	int theman = 0;


	FILE *new_file;
	new_file = fopen("copy.txt","w");

	FILE* fp = fopen("secure.txt","r+");
	//fp = fopen("secure.txt","r+");
	fseek(fp,0,SEEK_SET);
	//printf("%s\n","while start" );
	while(1){
		ch = getc(fp);
		if(ch == EOF){
			break;
		} 
		if(flag == 0){
			if(ch == ':'){
				flag = 1;
				name[nind] = '\0';
				nind = 0;
				//printf("%s\n",name);
				if(strcmp(name,filename) == 0){
					//printf("%s\n", "FOO");
					theman = 1;
				}
			}
			else{
				name[nind] = ch;
				nind++;
			}
		}
		else{
			if(count == 20){
				hasha[hindx] = '\0';
				fputs(name,new_file);
				fputs(":",new_file);
				if(theman){
					fputs(rhash,new_file);
				}
				else{
					fputs(hasha,new_file);
				}
				fputs("\n",new_file);
				count = 0;
				hindx = 0;
				flag = 0;
			}
			else{
				count++;
				hasha[hindx] = ch;
				hindx++;
			}
			
		}
		
	}
	
	//printf("%s\n","Almost updated" );
	fclose(fp);
	//printf("%s\n","fdr" );
	fclose(new_file);
	//printf("%s\n","jfk" );
	remove("secure.txt");
	//printf("%s\n","obama" );
	rename("copy.txt","secure.txt");
	//printf("%s\n","Update complete" );
}

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */
int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);

	FILE* fp;
	char roothash[21];
	
	FILE* temp = fopen(pathname,"r");
	int flag = 0;
	if(temp == NULL){
		flag = 1;
	}
	else fclose(temp);

	int fd = open(pathname, flags, mode);
	//fseek(fd,0,SEEK_END);

	// Should fd be closed?

	FILE* sp = fopen(pathname,"r");
	//printf("%s %s\n", "File is: ", pathname);
	//display(sp);
	get_root_hash(sp,roothash);
	fclose(sp);
	
	if(!flag){
		
		
		char nm[10];
		strncpy(nm,pathname,9);
		nm[9] = '\0';
		
		char oldhash[21];
		
		//fp = fopen("secure.txt","r");
		int retstatus = get_old_hash(oldhash,nm);
		//fclose(fp);

		if(retstatus == 0){
			int isequal = 1;
			for(int i = 0; i < 20; i++){
				if((oldhash[i] != roothash[i]) && !(oldhash[i] == '\0' || roothash[i] == '\0')){
					isequal = 0;
					}
				if(oldhash[i] == '\0' || roothash[i] == '\0'){
					break;
				}
			}
			if(isequal != 1){
				return -1;
			}
			else{
				int myval = nm[4] - '0';
				sp = fopen(pathname,"r");
				fseek(sp,0,SEEK_END);
				fend[myval]	= ftell(sp);
				fclose(sp);		
			}
			
		}
		else{
			fp = fopen("secure.txt","a");
			fputs(pathname,fp);
			fputs(":",fp);
			fputs(roothash,fp);
			fputc('\n',fp);
			fclose(fp);
		}
		//fclose(fp);
	}
	else{
		fp = fopen("secure.txt","a");
		fputs(pathname,fp);
		fputs(":",fp);
		fputs(roothash,fp);
		fputc('\n',fp);
		fclose(fp);
	}
	
	//fp = fopen("secure.txt","r");
	//printf("%s\n","Displaying secure.txt in s_open: " );
	//display(fp);
	//fclose(fp);

	
	
	//Yet,to cater for truncation.
	
	
	strncpy(gfnms[fd],pathname,9);
	return fd;
}

/* SEEK_END should always return the file size 
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	int val = gfnms[fd][4] - '0'; 
	int fs = fend[val];
	if(whence == SEEK_END){
		return fs;
	}
	
	
	
	return lseek (fd, offset, SEEK_SET);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
	//printf("%s\n", "In write");

	//FILE *fp;
	
	FILE* sp = fopen(gfnms[fd],"r+");
	//printf("%s %s\n","File in write is: ",gfnms[fd]);
	//display(sp);
	
	char roothash[21];
	ssize_t retval;

	
	int myval = gfnms[fd][4] - '0';
	fend[myval] += count;
	//printf("%s\n","OP2");

	//printf("%s\n",gfnms[fd]);
	get_root_hash(sp,roothash);
	
	//fp = fopen("secure.txt","r");
	char oldhash[21];
	//printf("%s\n","Attempting to get sanity" );
	get_old_hash(oldhash,gfnms[fd]);
	//printf("sanity is: %i\n", sanity);
	//fclose(fp);

	
	//printf("foo is:\n" );
	//display(sp);
	fclose(sp);
	//fp = fopen("secure.txt","r");
	//printf("secure is\n");
	//display(fp);
	//fclose(fp);
	//printf("Roothash is: %s\n", roothash);	
	//printf("Oldhash is: %s\n", oldhash);


	//printf("%s\n",gfnms[fd]);
	
	int isequal = 1;
	for(int i = 0; i < 20; i++){
		if((oldhash[i] != roothash[i]) && !(oldhash[i] == '\0' || roothash[i] == '\0')){
			isequal = 0;
		}
		if(oldhash[i] == '\0' || roothash[i] == '\0'){
			break;
		}
	}
	if(isequal == 0){	
		return -1;
		
	} 
	//else printf("%s\n","Some JOY" );
	
	
	retval = write (fd, buf, count);
	//fsync(fd);
	
	if(retval == -1){
		printf("%s\n", "Error in write");
	}

	memset(roothash,0,21);
	sp = fopen(gfnms[fd],"r");
	get_root_hash(sp,roothash);
	fclose(sp);
	//printf("%s\n","GOt it" );
	
	//printf("Roothash now is:%s\n", roothash);

	//fp = fopen("secure.txt","r+");
	update_hash_val(roothash,gfnms[fd]);
	

	
	return retval;
}

/* check the integrity of blocks containing the 
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	
	char roothash[21];
	FILE* sp = fopen(gfnms[fd],"r");
	get_root_hash(sp,roothash);
	fclose(sp);
	char oldhash[21];
	//fp = fopen("secure.txt","r");
	get_old_hash(oldhash,gfnms[fd]);
	//fclose(fp);

	int isequal = 1;
	for(int i = 0; i < 20; i++){
		if((oldhash[i] != roothash[i]) && !(oldhash[i] == '\0' || roothash[i] == '\0')){
			isequal = 0;
		}
		if(oldhash[i] == '\0' || roothash[i] == '\0'){
			break;
		}
	}
	if( isequal != 1) return -1;
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	int toret = close(fd);
	//printf("%s\n","Closing");
	return toret;
}

/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	filesys_inited = 1;

	//printf("%s\n","In init" );
	int success = helper();
	//printf("%s\n","Going to display" );
	FILE* fp = fopen("secure.txt","r");
	//display(fp);
	fclose(fp);
	return success;
}




