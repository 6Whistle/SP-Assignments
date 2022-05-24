//////////////////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c						     //
// Date 	: 2022/05/25						     //
// OS		: Ubuntu 16.04 LTS 64bits				     //
// Author	: Jun Hwei Lee						     //
// Student ID	: 2018202046						     //
//---------------------------------------------------------------------------//
// Title : System Programming Assignment #2-4 (proxy server)		     //
// Description :  Make Socket and wait client		    		     //
//                if client connected, Get URL from client          	     //
//                Write Cache and Log using URL and Response  	    	     //
//		  if miss state, connect with web server		     //
//                signal SIGALRM Handing				     //
//                Send cache data to client	  	     		     //
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>		//printf()
#include <stdlib.h>  		//exit()
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
#include <netdb.h>      //gethostbyname()
#include <fcntl.h>

#define BUFFSIZE 1024
#define PORTNO 39999
#define WEBPORTNO 80

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
// AlarmHandler								      //
//============================================================================//
// Purpose : Handling ALRM signal					      //
////////////////////////////////////////////////////////////////////////////////

static void AlarmHandler(){
  printf("============== No Response ================\n");
  exit(0);
}


////////////////////////////////////////////////////////////////////////////////
// getIPAddr								      //
//============================================================================//
// Input : char *addr -> Input URL,					      //
// Output : char * -> IPv4 address					      //
// Purpose : Get IPv4 address from URL					      //
////////////////////////////////////////////////////////////////////////////////

char *getIPAddr(char *addr) {
  struct hostent* hent;
  char *haddr = NULL;
  char temp[BUFFSIZE];
  char *token = NULL;
  int len = strlen(addr);

  //Get URL Domain
  strcpy(temp, addr);
  strtok(temp, "//");
  token = strtok(NULL, "/");

  //Get Host address using Domain
  if((hent = (struct hostent*)gethostbyname(token)) != NULL)
    haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
  return haddr;
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
// Check_Cache_Print_Web						      //
//============================================================================//
// Input : int client_fd -> client's file descriptor		              // 
//    char *url -> URL name,						      //
//    char *cache_dir -> cache directory path,			     	      //
//    char *log_file -> logfile path,					      //
//    char *buf -> Client's request,					      //
//    int current_pid -> current process ID,				      //
//    int len -> buf's length,						      //
//    int *hit -> count of hit,						      //
//    int *miss -> count of miss,					      //
// Output : int -> URL HIT : 1, MISS : 0			       	      //
// Purpose : Make URL's Cache directory and check state(hit or miss)	      //
//	     If Miss state, save Response msg from Web, and send to client    //
//	     If Hit state, read cache file, and send to client		      //
////////////////////////////////////////////////////////////////////////////////

int Check_Cache_Print_Web(int client_fd, char *url, char *cache_dir, char *log_file, char *buf, int current_pid, int len, int* hit, int* miss){
  char hashed_url[60];		//Store hashed URL using SHA1
  char first_dir[4];		//Directory that will be made in cache directory  
  char *dir_div;		//Seperate point of hashed URL name
  char temp_dir[100];		//Path is used when it makes directory or file 
  char *haddr = NULL;
  char h_buf[BUFFSIZE] = {0, };
  int h_socket_fd, cache_fd, h_len;
  int is_exist_file = 1;

  struct sockaddr_in web_server_addr;

  bzero(h_buf, sizeof(h_buf));

  sha1_hash(url, hashed_url);	//URL -> hashed URL
  strncpy(first_dir, hashed_url, 3);	//Directory name <- hashed URL[0~2]
  first_dir[3] = '\0';
  dir_div = hashed_url + 3;		//File name pointer

  strcpy(temp_dir, cache_dir);		//Make directory ~/cache/Directory name (permission : rwxrwxrwx)
  strcat(temp_dir, "/");
  strcat(temp_dir, first_dir);
  if(mkdir(temp_dir, 0777) == 0)    //Directory isn't already exist, is_exist_file is 0 
    is_exist_file = 0;

  is_exist_file = Check_Exist_File(temp_dir, dir_div, is_exist_file);   //Check ~/cache/Directory name/File name is exist
  Write_Log_File(log_file, current_pid, url, first_dir, dir_div, is_exist_file, hit, miss);    //Write the state(hit or miss) in logfile.txt
  
  strcat(temp_dir, "/");		//Make empty file ~/cache/Directory name/File name (premission : rwxrwxrwx)
  strcat(temp_dir, dir_div);

  //if state is miss, get connection with web server
  if(is_exist_file == 0){
    haddr = getIPAddr(url);   //Get host's IP address
    if((h_socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){    //Make socket descriptor
      printf("can't creat socket.\n");
      close(h_socket_fd);
      exit(0);
    }

    //Web server's address
    bzero((char*)&web_server_addr, sizeof(web_server_addr));
    web_server_addr.sin_family = AF_INET;
    web_server_addr.sin_addr.s_addr = inet_addr(haddr);
    web_server_addr.sin_port = htons(WEBPORTNO);
  
    //Connect with Web server
    if(connect(h_socket_fd, (struct sockaddr*)&web_server_addr, sizeof(web_server_addr)) < 0){
      printf("can't connect.\n");
      close(h_socket_fd);
      exit(0);
    }

    //SIGALRM Handler
    signal(SIGALRM, AlarmHandler);
    
    alarm(20);      //Wait 10 sec
    //sleep(5);    //Connection error case
    
    cache_fd = open(temp_dir, O_WRONLY | O_CREAT | O_APPEND, 0777);   //Create file
    write(h_socket_fd, buf, BUFFSIZE);     //Send request to web server
    while(h_len = read(h_socket_fd, h_buf, BUFFSIZE)){  //Read data from web server
      alarm(0);    //if Get data from web, alarm off
      write(cache_fd, h_buf, h_len);      //Write data in cache file
      write(client_fd, h_buf, h_len);     //Send data to client
      bzero(h_buf, sizeof(h_buf));
    }
    close(h_socket_fd);
  }
  else{     //if state is hit, read cache file and send it to client
    cache_fd = open(temp_dir, O_RDONLY);    //Open read mode
    while(h_len = read(cache_fd, h_buf, BUFFSIZE)){   //Read all of data in cache file
      write(client_fd, h_buf, BUFFSIZE);    //Send data to client
      bzero(h_buf, sizeof(h_buf));
    }
  }
  close(cache_fd);
  return is_exist_file;
}



////////////////////////////////////////////////////////////////////////////////
// Sub_Process_Work							      //
//============================================================================//
// Input : char *client_fd -> client's file descriptor,			      //
//         struct sockaddr_in *client_addr -> client's address info,          //
//         char *buf -> input buffer,     				      //
//         char *cache_dir -> ~/cache path,				      //
//         FILE *log_dir -> Write ~/logfile/logfile.txt,		      //
// Output : void						       	      //
// Purpose : recieve message from client and check URL from  Cache            //
//           send response message to client				      //
////////////////////////////////////////////////////////////////////////////////

void Sub_Process_Work(int client_fd, struct sockaddr_in client_addr, char *buf, char *cache_dir, char *log_dir){  
  char tmp[BUFFSIZE] = {0, };
  char method[BUFFSIZE] = {0, };      //recieve method
  char url[BUFFSIZE] = {0, };         //recieve URL
  char *token = NULL;                 //tokenizer
  int len;
  int state;              //HIT or MISS exist 
  int hit = 0, miss = 0;  //Count hit and miss

  FILE *log_file;     //log_file's path
  FILE *temp_file;		//Using when make a empty file
  pid_t current_pid = getpid();   //Current process id
  time_t start_process_time, end_process_time;    //Process start and end time
  
  time(&start_process_time);  //Check process start time
  bzero(buf, BUFFSIZE);       //buffer clear

  //Read Data From client File Descriptor
  while((len = read(client_fd, buf, BUFFSIZE)) > 0){
    strcpy(tmp, buf);                       //Copy message and print it
    printf("================================================\n");
    printf("Request from [%s : %d]\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
    printf("%s", buf);
    printf("================================================\n");

    //Divide method and url from message
    token = strtok(tmp, " ");
    strcpy(method, token);
    //if method is GET, Make Cache and send response
    if(strcmp(method, "GET") == 0){
      token = strtok(NULL, " ");
      strcpy(url, token);
      state = Check_Cache_Print_Web(client_fd, url, cache_dir, log_dir, buf, current_pid, len, &hit, &miss);
    }

    time(&end_process_time);      //check end process time
    log_file = fopen(log_dir, "a");
    fprintf(log_file, "[Terminated] ServerPID : %d | run time: %d sec #request hit : %d, miss : %d\n",
    current_pid, (int)(end_process_time-start_process_time), hit, miss);   //write whitch client was terminated, process execute time, hit, miss in logfile.txt
    fclose(log_file);
  }
  return;         //end program
}


void main(void){
  char buf[BUFFSIZE];     //buffer
  char cache_dir[100];   //Cache directory
  char log_dir[100];    //Log directory
  int process_count = 0;    //Count sub-process
  int socket_fd, client_fd;   //socket and client file descriptor
  int len, len_out;       //length of buffer          
  int opt = 1;

  struct sockaddr_in server_addr, client_addr;    //server address and client address

  FILE *log_file;     //Using when write log file
  pid_t pid;          //child pid

  Make_Cache_Dir_Log_File(cache_dir, log_dir);    //Make cache and log directory, and update path

  if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){    //if can't open socket, return with error
    printf("Server : Can't open stream socket\n");
    return;
  }
  setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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
      printf("[%s | %d] Client was connected\n",inet_ntoa(client_addr.sin_addr),  client_addr.sin_port);    //Print whitch Client is connected and pid number
      Sub_Process_Work(client_fd, client_addr, buf, cache_dir, log_dir);
      printf("[%s | %d] Client was disconnected\n\n", inet_ntoa(client_addr.sin_addr) , client_addr.sin_port);  //print whitch client was terminated and pid number
      close(client_fd);
      exit(0);
    }
    close(client_fd);   //Main process close file descriptor
  }
  close(socket_fd);   //Close socket file descriptor
}
