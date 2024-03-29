///////////////////////////////////////////////////////////////////////////////
// File Name	: server.c						     //
// Date 	: 2022/04/26						     //
// OS		: Ubuntu 16.04 LTS 64bits				     //
// Author	: Jun Hwei Lee						     //
// Student ID	: 2018202046						     //
//---------------------------------------------------------------------------//
// Title : System Programming Assignment #2-1 (proxy server)		     //
// Description :  Make Socket and wait client		    		     //
//                if client connected, Get URL from client          	     //
//                Make Cache and Log using URL  	     		     //
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>		//printf()
#include <stdlib.h>   //exit()
#include <string.h>		//strcpy()
#include <openssl/sha.h>	//SHA1()
#include <sys/types.h>		//getHomeDir()
#include <unistd.h>		//getHomeDir()
#include <pwd.h>		//getHomeDir()
#include <sys/stat.h>		//mkdir()
#include <dirent.h>   //openDir()
#include <time.h>     //Write_Log_File()
#include <sys/wait.h>   //waitpid()
#include <sys/socket.h> //socket()
#include <signal.h>     //signal()
#include <netinet/in.h> //htonl()
#include <arpa/inet.h>  //inet_ntoa()

#define BUFFSIZE 1024
#define PORTNO 40000

////////////////////////////////////////////////////////////////////////////////
// handler								      //
//============================================================================//
// Purpose : Handling child process					      //
////////////////////////////////////////////////////////////////////////////////

static void handler(){
    pid_t pid;
    int status;
    while((pid = waitpid(-1, &status, WNOHANG)) > 0);     //Wait Any child with WNOHANG
}


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
// Make_Cache_Dir_Log_File						      //
//============================================================================//
// Input : char *cache_dir -> Store cache directory's path	 	      //
//         char *log_file -> Store log file's path,		     	      //
// Purpose : Make cache and logfile Directory. Store path		      //
////////////////////////////////////////////////////////////////////////////////

void Make_Cache_Dir_Log_File(char* cache_dir, char* log_file){
  char home_dir[100];		//Current user's home directory

  getHomeDir(home_dir);		//Find ~ directory

  strcpy(cache_dir, home_dir);
  strcat(cache_dir, "/cache");    //cache_dir = ~/cache
  strcpy(log_file, home_dir);
  strcat(log_file, "/logfile");    //log_file = ~/logfile

  umask(000);			//Directory's permission can be drwxrwxrwx
  mkdir(cache_dir, 0777);	//make ~/cache Directory
  mkdir(log_file, 0777);   //make ~/logfile Directory
  
  strcat(log_file, "/logfile.txt");   //Open ~/logfile/logfile.txt (read, write, append mode)
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
// Input : File *log_dir -> opened file pointer,			      //
//    char *input_url -> input URL,				     	      //
//    char *hashed_url_dir -> hashed directory name,			      //
//    char *hashed_url_file -> hashed file name,			      //
//    char is_exist_file -> if directory/file is exist : 1, else : 0, 	      //
//    int *hit -> count of hit,						      //
//    int *miss -> count of miss,					      //
// Output : void						       	      //
// Purpose : Write that is input URL hit or miss in log file		      //
////////////////////////////////////////////////////////////////////////////////

void Write_Log_File(char *log_dir, int cur_pid, char *input_url, char *hashed_url_dir, char *hashed_url_file, int is_exist_file, int *hit, int *miss){
  FILE *log_file;
  time_t now;       //Current time
  struct tm *ltp;   //Local time


  time(&now);       //Save Current time
  ltp = localtime(&now);
  log_file = fopen(log_dir, "a");
  if(is_exist_file == 0){   //if file isn't exist, write miss state at logfile.txt
    fprintf(log_file, "[MISS] ServerPID : %d | %s-[%d/%d/%d, %02d:%02d:%02d]\n",
    cur_pid, input_url, ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
    (*miss)++;    //miss count
  }
  else{   //if file is exist, write hit state at logfile.txt
    fprintf(log_file, "[HIT] ServerPID : %d | %s/%s-[%d/%d/%d, %02d:%02d:%02d]\n",
    cur_pid, hashed_url_dir, hashed_url_file, ltp->tm_year+1900, ltp->tm_mon+1, ltp->tm_mday, ltp->tm_hour, ltp->tm_min, ltp->tm_sec);
    fprintf(log_file, "[HIT]%s\n", input_url);
    (*hit)++;     //hit count
  }
  fclose(log_file);
}

////////////////////////////////////////////////////////////////////////////////
// Sub_Process_Work							      //
//============================================================================//
// Input : char *client_fd -> client's file descriptor,			      //
//         struct sockaddr_in *client_addr -> client's address info,          //
//         char *buf -> input buffer,     				      //
//         char *cache_dir -> ~/cache path,				      //
//         FILE *log_file -> Write ~/logfile/logfile.txt,		      //
// Output : void						       	      //
// Purpose : Make hashed url directory and file in ~/cache/,	              //
//           write hit and miss state in ~/logfile/logfile.txt		      //
////////////////////////////////////////////////////////////////////////////////

void Sub_Process_Work(int client_fd, struct sockaddr_in client_addr, char *buf, char *cache_dir, char *log_dir){
  char hashed_url[60];		//Store hashed URL using SHA1
  char first_dir[4];		//Directory that will be made in cache directory  
  char *dir_div;		//Seperate point of hashed URL name
  char temp_dir[100];		//Path is used when it makes directory or file 

  int len_out;
  int is_exist_file;  //State directory/file is exist
  int hit = 0, miss = 0;  //Count hit and miss

  FILE *log_file;     //log_file's path
  FILE *temp_file;		//Using when make a empty file
  pid_t current_pid = getpid();   //Current process id
  time_t start_process_time, end_process_time;    //Process start and end time
  
  time(&start_process_time);  //Check process start time
  bzero(buf, BUFFSIZE);       //buffer clear
  printf("[%s | %d] Client was connected\n",inet_ntoa(client_addr.sin_addr),  client_addr.sin_port);    //Print whitch Client is connected and pid number

  //Read Data From client File Descriptor
  while((len_out = read(client_fd, buf, BUFFSIZE)) > 0){
    buf[len_out-1] = '\0';
    is_exist_file = 1;
    sha1_hash(buf, hashed_url);	//URL -> hashed URL
    strncpy(first_dir, hashed_url, 3);	//Directory name <- hashed URL[0~2]
    first_dir[3] = '\0';
    dir_div = hashed_url + 3;		//File name pointer

    strcpy(temp_dir, cache_dir);		//Make directory ~/cache/Directory name (permission : rwxrwxrwx)
    strcat(temp_dir, "/");
    strcat(temp_dir, first_dir);
    if(mkdir(temp_dir, 0777) == 0)    //Directory isn't already exist, is_exist_file is 0 
      is_exist_file = 0;

    is_exist_file = Check_Exist_File(temp_dir, dir_div, is_exist_file);   //Check ~/cache/Directory name/File name is exist
    Write_Log_File(log_dir, current_pid, buf, first_dir, dir_div, is_exist_file, &hit, &miss);    //Write the state(hit or miss) in logfile.txt

    strcat(temp_dir, "/");		//Make empty file ~/cache/Directory name/File name (premission : rwxrwxrwx)
    strcat(temp_dir, dir_div);
    temp_file = fopen(temp_dir, "a+");
    fclose(temp_file);

    bzero(buf, BUFFSIZE);

    if(is_exist_file)       //if HIT state, buf = HIT
      strncat(buf, "HIT", 3);
    else
      strncat(buf, "MISS", 4);  //if MISS state, buf = MISS
    write(client_fd, buf, strlen(buf));   //Send state data to client file descriptor
    bzero(buf, BUFFSIZE);     //buffer clear
  }
  
  time(&end_process_time);      //check end process time
  log_file = fopen(log_dir, "a");
  fprintf(log_file, "[Terminated] ServerPID : %d | run time: %d sec #request hit : %d, miss : %d\n",
  current_pid, (int)(end_process_time-start_process_time), hit, miss);   //write whitch client was terminated, process execute time, hit, miss in logfile.txt
  fclose(log_file);
  printf("[%s | %d] Client was disconnected\n", inet_ntoa(client_addr.sin_addr) , client_addr.sin_port);  //print whitch client was terminated and pid number
  return;         //end program
}


void main(void){
  char buf[BUFFSIZE];     //buffer
  char cache_dir[100];   //Cache directory
  char log_dir[100];    //Log directory
  int process_count = 0;    //Count sub-process
  int socket_fd, client_fd;   //socket and client file descriptor
  int len, len_out;       //length of buffer          

  struct sockaddr_in server_addr, client_addr;    //server address and client address

  FILE *log_file;     //Using when write log file
  pid_t pid;          //child pid

  Make_Cache_Dir_Log_File(cache_dir, log_dir);    //Make cache and log directory, and update path

  if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){    //if can't open socket, return with error
    printf("Server : Can't open stream socket\n");
    return;
  }

  //Server address information update
  bzero((char*)&server_addr, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(PORTNO);

  //if can't ind socket file descriptor and address information, return with error
  if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    printf("Server : Can't bind local address\n");
    close(socket_fd);
    return;
  }

  listen(socket_fd, 5);         //wait for client's connect
  signal(SIGCHLD, (void *)handler);   //catch SIGCHID signal

  while(1){
    //accept client's connection request
    bzero((char*)&client_addr, sizeof(client_addr));
    len = sizeof(client_addr);
    client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &len);

    //if faild to accept, return with error
    if(client_fd < 0){
      printf("Server : accept failed\n");
      close(socket_fd);
      return;
    }

    //if failed to make child process, close client file descriptor   
    if((pid = fork()) == -1){
      close(client_fd);
      close(socket_fd);
      continue;
    }
    if(pid == 0){   //Do sub process work in child process
      Sub_Process_Work(client_fd, client_addr, buf, cache_dir, log_dir);
      close(client_fd);
      exit(0);
    }
    close(client_fd);   //Main process close file descriptor
  }
  close(socket_fd);   //Close socket file descriptor
}
