///////////////////////////////////////////////////////////////////////////////
// File Name	: client.c						     //
// Date 	: 2022/04/26						     //
// OS		: Ubuntu 16.04 LTS 64bits				     //
// Author	: Jun Hwei Lee						     //
// Student ID	: 2018202046						     //
//---------------------------------------------------------------------------//
// Title : System Programming Assignment #2-1 (proxy server)		     //
// Description :  Client connect to Local Server			     //
//                if client connected, Send URL to server	             //
//                Print HIT or MISS  	    			  	     //
///////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>     //strncmp(), bzero()
#include <unistd.h>     //UNIX standard  
#include <sys/socket.h> //socket()
#include <netinet/in.h> //PF_INET
#include <arpa/inet.h>  //inet_addr()

#define BUFFSIZE 1024
#define PORTNO 40000

int main(void){
    int socket_fd, len;     //socket file descriptor, buffer's length
    struct sockaddr_in server_addr; //server's address information
    char haddr[] = "127.0.0.1";     //Local IP
    char buf[BUFFSIZE];             //buffer

    //if can't open socket, return with error
    if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        printf("can't create socket.\n");
	close(socket_fd);
        return -1;
    }

    //Input Server's address information
    bzero(buf, sizeof(buf));
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(haddr);
    server_addr.sin_port = htons(PORTNO);

    //If failed to connect, return with error
    if(connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("can't connect.\n");
        return -1;
    }

    //while can get user's input
    write(STDOUT_FILENO, "input url > ", 12);
    while((len = read(STDIN_FILENO, buf, sizeof(buf))) > 0){
        //if URL is bye, break loop
        if(strncmp(buf, "bye", 3) == 0)
            break;
        //if Sending to server is successed
        if(write(socket_fd, buf, strlen(buf)) > 0){
            bzero(buf, BUFFSIZE);
            //if Recieve data from server, print it
            if((len = read(socket_fd, buf, sizeof(buf)) > 0)){
                write(STDOUT_FILENO, buf, strlen(buf));
                write(STDOUT_FILENO, "\n", 1);
                bzero(buf, sizeof(buf));
            }
            write(STDOUT_FILENO, "input url > ", 12);
        }
    }
    close(socket_fd);
    return 0;
}
