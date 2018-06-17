#ifndef __SOCK_H
#define __SOCK_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

/* ===== API for simple INET/UNIX socket ===== */


/*
   Create a server
   If port is valid, create an INET server.
   Otherwise, create an UNIX server.
   Return serverfd for OK, negetive value for ERR
   Example:
       [INET Server]
       int serverfd;
       if ((serverfd = sock_server(2333, NULL, 5)) < 0)
       {
           prinf("Error: fail to create server\n");
       }
       [UNIX Server]
       int serverfd;
       if ((serverfd = sock_server(-1, "test.sock", 5)) < 0)
       {
           prinf("Error: fail to create server\n");
       }
*/
int sock_server(int port, const char *sockfile, int queue_length);

/*
   Accept a client and create a session
   Return sessionfd for OK, negetive value for ERR
   Example:
       int sessionfd;
       if ((sessionfd = sock_accept(serverfd, addr, addrlen)) < 0)
       {
           prinf("Error: fail to accept client\n");
       }
*/
int sock_accept(int serverfd, struct sockaddr *addr, socklen_t *addrlen);

/*
   Create a client connected to a server
   If host and port are valid, create an INET client.
   Otherwise, create an UNIX client.
   Return clientfd for OK, negetive value for ERR
   Example:
       [INET Client]
       int clientfd;
       if ((clientfd = sock_client("127.0.0.1", 2333, NULL)) < 0)
       {
           printf("Error: fail to create client\n");
       }
       [UNIX Client]
       int clientfd;
       if ((clientfd = sock_client(NULL, -1, "test.sock")) < 0)
       {
           prinf("Error: fail to create client\n");
       }
*/
int sock_client(const char *host, int port, const char *sockfile);

/*
   Close a server/client/session
   Example:
       close(clientfd);
       close(sessionfd);
       close(serverfd);
*/
void sock_close(int fd);


/*
   Send message
   Return message length sent for OK, negetive value for ERR
   Example:
       if ((sock_send(clientfd, msg, msg_len) < 0)
       {
           printf("Error: fail to send message\n");
       }
*/
ssize_t sock_send(int sockfd, const void *buf, size_t len);

/*
   Receive message
   Return message length received for OK, negetive value for ERR
   Example:
       if ((msg_len = sock_recv(sessionfd, buf, MAX_LEN) < 0)
       {
           printf("Error: fail to receive message\n");
       }
*/
ssize_t sock_recv(int sockfd, void *buf, size_t len);

/*
   Sock Example:

   [Sever]
	int serverfd;
	int sessionfd;
	char buf[512];
	int len;
	if ((serverfd = sock_server(-1, "test.sock", 5)) < 0)
	{
		exit(-1);
	}
	if ((sessionfd = sock_accept(serverfd)) < 0)
	{
		exit(-2);
	}
	if ((len = sock_recv(sessionfd, buf, 512)) > 0)
	{
		buf[len] = 0;
		printf("Recv: %s\n", buf);
	}
	sock_close(sessionfd);
	sock_close(serverfd);	

   [Client]
	int clientfd;
	char buf[512];
	int len;
	if ((clientfd = sock_client(NULL, -1, "test.sock")) < 0)
	{
		exit(-1);
	}
	sprintf(buf, "Hello world");
	len = strlen(buf);
	if ((len = sock_send(clientfd, buf, len)) > 0)
	{
		printf("Send: %s\n", buf);
	}
	sock_close(clientfd);
*/

#endif
