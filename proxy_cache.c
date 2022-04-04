///////////////////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c						     //
// Date 	: 2022/03/24						     //
// OS		: Ubuntu 16.04 LTS 64bits				     //
// Author	: Jun Hwei Lee						     //
// Student ID	: 2018202046						     //
//---------------------------------------------------------------------------//
// Title : System Programming Assignment #1-1 (proxy server)		     //
// Description : 	Making Cache Directory with hashed URL		     //
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>		//printf()
#include <string.h>		//strcpy()
#include <openssl/sha.h>	//SHA1()
#include <sys/types.h>		//getHomeDir()
#include <unistd.h>		//getHomeDir()
#include <pwd.h>		//getHomeDir()
#include <sys/stat.h>		//mkdir()
#include <dirent.h>   //openDir()
#include <time.h>     //Write_Log_File()


////////////////////////////////////////////////////////////////////////////////
// sha1_hash								      //
//============================================================================//
// Input : char *input_url -> Input URL,				      //
// 	   char *hashed_url -> Hashed URL using SHA1			      //
// Output : char * -> Hashed URL using SHA1				      //
// Purpose : Hashing URL						      //
////////////////////////////////////////////////////////////////////////////////

char *sha1_hash(char *input_url, char *hashed_url) {
  unsigned char hashed_160bits[20];
  char hashed_hex[41];
  int i;

  SHA1(input_url, strlen(input_url), hashed_160bits);

  for(i = 0; i < sizeof(hashed_160bits); i++)
	  sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);

  strcpy(hashed_url, hashed_hex);

  return hashed_url;
}


////////////////////////////////////////////////////////////////////////////////
// getHomeDir								      //
//============================================================================//
// Input : char *home -> Store home directory				      //
// Output : char * -> Print home directory				      //
// Purpose : Finding Current user's home				      //
////////////////////////////////////////////////////////////////////////////////

char *getHomeDir(char *home){
  struct passwd *usr_info = getpwuid(getuid());
  strcpy(home, usr_info->pw_dir);

  return home;
}


////////////////////////////////////////////////////////////////////////////////
// Check_Exist_File							      //
//============================================================================//
// Input : char *path -> Directory's path,				      //
//    char *file_name -> file name,				     	      //
//    char is_exist_file -> if directory is exist : 1, else : 0, 	      //
// Output : int -> if path/file is exist : return 1, else : return 0	      //
// Purpose : Checking path/file is exist				      //
////////////////////////////////////////////////////////////////////////////////

int Check_Exist_File(char* path, char *file_name, int is_exist_file){
  if(is_exist_file == 0){         //if Directory isn't exist, return 0
    return 0;
  }

  DIR *dir = opendir(path);       //Open path directoy
  struct dirent *d;

  while(d = readdir(dir))         //Check path directory
    if(strcmp(d->d_name, file_name) == 0){    //if file name is exist, return 1
      closedir(dir);
      return 1;
    }
  
  closedir(dir);        //if file name isn't  exist, return 0
  return 0;
}


////////////////////////////////////////////////////////////////////////////////
// Write_Log_File							      //
//============================================================================//
// Input : File *log_file -> opened file pointer,			      //
//    char *input_url -> input URL,				     	      //
//    char *hashed_url_dir -> hashed directory name,			      //
//    char *hashed_url_file -> hashed file name,			      //
//    char is_exist_file -> if directory/file is exist : 1, else : 0, 	      //
//    int *hit -> count of hit,						      //
//    int *miss -> count of miss,					      //
// Output : void						       	      //
// Purpose : Write that is input URL hit or miss in log file		      //
////////////////////////////////////////////////////////////////////////////////

void Write_Log_File(FILE *log_file, char *input_url, char *hashed_url_dir, char *hashed_url_file, int is_exist_file, int *hit, int *miss){
  time_t now;       //Current time
  struct tm *ltp;   //Local time

  time(&now);       //Save Current time
  ltp = localtime(&now);

  if(is_exist_file == 0){   //if file isn't exist, write miss state at logfile.txt
    fprintf(log_file, "[MISS]%s-[%d/%d/%d, %02d:%02d:%02d]\n", input_url, ltp->tm_year+1900, ltp->tm_mon, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
    (*miss)++;    //miss count
  }
  else{   //if file is exist, write hit state at logfile.txt
    fprintf(log_file, "[HIT]%s/%s-[%d/%d/%d, %02d:%02d:%02d]\n", hashed_url_dir, hashed_url_file, ltp->tm_year, ltp->tm_mon, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
    fprintf(log_file, "[HIT]%s\n", input_url);
    (*hit)++;     //hit count
  }
}


void main(void){
  char input[100];		//Store input Data(URL or bye
  char hashed_url[60];		//Store hashed URL using SHA1
  char home_dir[100];		//Current user's home directory
  char cache_dir[100];   //Cache directory
  char log_dir[100];    //Log directory
  char first_dir[4];		//Directory that will be made in cache directory
  char *dir_div;		//Seperate point of hashed URL name
  char temp_dir[100];		//Path is used when it makes directory or file
  
  int is_exist_file;  //State directory/file is exist
  int hit = 0;      //Count hit
  int miss = 0;     //Count miss

  FILE *temp_file;		//Using when make a empty file
  FILE *log_file;     //Using when write log file

  time_t start_time;  //Program start time
  time_t end_time;    //Program end time

  time(&start_time);    //Check Start time

  getHomeDir(home_dir);		//Find ~ directory

  strcpy(cache_dir, home_dir);
  strcat(cache_dir, "/cache");    //cache_dir = ~/cache

  strcpy(log_dir, home_dir);
  strcat(log_dir, "/logfile");    //log_dir = ~/logfile

  umask(000);			//Directory's permission can be drwxrwxrwx
  mkdir(cache_dir, 0777);	//make ~/cache Directory
  mkdir(log_dir, 0777);   //make ~/logfile Directory
  
  strcpy(temp_dir, log_dir);
  strcat(temp_dir, "/logfile.txt");   //Open ~/logfile/logfile.txt (read, write, append mode)
  log_file = fopen(temp_dir, "a+");
  fseek(log_file, 0, SEEK_END);       //file pointer is in the end of file

  while(1){
    printf("input url> ");	//get URL
    scanf("%s", input);
    if(strcmp(input, "bye") == 0){	//if it's 'bye' command, write log at logfile.txt and end program
      
      time(&end_time);      //check end time
      fprintf(log_file, "[Terminated] run time: %d sec #request hit : %d, miss : %d\n", (int)(end_time-start_time), hit, miss);   //write execute time, hit, miss in logfile.txt
      fclose(log_file);
      return;         //end program
    }
      
    is_exist_file = 1;
    sha1_hash(input, hashed_url);	//URL -> hashed URL
    strncpy(first_dir, hashed_url, 3);	//Directory name <- hashed URL[0~2]
    first_dir[3] = '\0';
    dir_div = hashed_url + 3;		//File name pointer

    strcpy(temp_dir, cache_dir);		//Make directory ~/cache/Directory name (permission : rwxrwxrwx)
    strcat(temp_dir, "/");
    strcat(temp_dir, first_dir);
    if(mkdir(temp_dir, 0777) == 0)    //Directory isn't already exist, is_exist_file is 0 
      is_exist_file = 0;

    is_exist_file = Check_Exist_File(temp_dir, dir_div, is_exist_file);   //Check ~/cache/Directory name/File name is exist
    Write_Log_File(log_file, input, first_dir, dir_div, is_exist_file, &hit, &miss);    //Write the state(hit or miss) in logfile.txt

    strcat(temp_dir, "/");		//Make empty file ~/cache/Directory name/File name (premission : rwxrwxrwx)
    strcat(temp_dir, dir_div);
    temp_file = fopen(temp_dir, "w");
    fclose(temp_file);
  }
}
