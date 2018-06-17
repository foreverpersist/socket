#include "sock.h"

int sock_server(int port, const char *sockfile, int queue_length)
{
	int domain;
	struct sockaddr *addr;
	int serverfd;
	struct sockaddr_in in;
	struct sockaddr_un un;
	int len;
	
	/* Parse socket type  */
	if (port >= 0)
	{
		domain = AF_INET;
		addr = (struct sockaddr *) &in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		in.sin_addr.s_addr = htonl(INADDR_ANY);
		in.sin_port = htons(port);
		len = sizeof(in);	
	}
	else if (sockfile != NULL)
	{
		domain = AF_UNIX;
		addr = (struct sockaddr *) &un;
		/* Remove old file if it exists */
		unlink(sockfile);
		memset(&un, 0, sizeof(un));
		un.sun_family = AF_UNIX;
		strcpy(un.sun_path, sockfile);
		len = offsetof(struct sockaddr_un, sun_path) + strlen(sockfile);
	}
	else
	{
		return -1;
	}
	/* Create socket */
	if ((serverfd = socket(domain, SOCK_STREAM, 0)) < 0)
	{
		return -2;
	}
	/* Bind socket */
	if (bind(serverfd, addr, len) < 0)
	{
		close(serverfd);
		return -3;
	}
	/* Start listening */
	if (listen(serverfd, queue_length) < 0)
	{
		close(serverfd);
		return -4;
	}

	return serverfd;
}

int sock_accept(int serverfd, struct sockaddr *addr, socklen_t *addrlen)
{
	int sessionfd;
	/* Accept client connection */
	if ((sessionfd = accept(serverfd, addr, addrlen)) < 0)
	{
		return -1;
	}

	return sessionfd;
}

int sock_client(const char *host, int port, const char *sockfile)
{
	int domain;
	int clientfd;
	struct sockaddr *addr;
	struct sockaddr_in in;
	struct hostent *h;
	struct sockaddr_un un;
	int len;

	/* Parse socket type */
	if (host != NULL && port > 0)
	{
		domain = AF_INET;
		addr = (struct sockaddr *) &in;
		memset(&in, 0, sizeof(in));
		in.sin_family = AF_INET;
		/* Read ip */
		if (inet_pton(AF_INET, host, &in.sin_addr) <= 0)
		{
			/* Failed to read ip from host, try gethostbyname */
			if ((h = gethostbyname(host)) == NULL)
			{
				return -1;
			}
			memcpy(&in.sin_addr.s_addr, h->h_addr, 4);
		}
		in.sin_port = htons(port);
		len = sizeof(in);
	}
	else if (sockfile != NULL)
	{
		domain = AF_UNIX;
		addr = (struct sockaddr *) &un;
		memset(&un, 0, sizeof(un));
		un.sun_family = AF_UNIX;
		strcpy(un.sun_path, sockfile);
		len = offsetof(struct sockaddr_un, sun_path) + strlen(sockfile);
	}
	/* Create socket */
	if ((clientfd = socket(domain, SOCK_STREAM, 0)) < 0 )
	{
		return -2;
	}
	/* Connect server */
	if (connect(clientfd, addr, len) < 0)
	{
		close(clientfd);
		return -3;
	}

	return clientfd;
}

void sock_close(int fd)
{
	close(fd);
}

ssize_t sock_send(int sockfd, const void *buf, size_t len)
{
	return send(sockfd, buf, len, 0);
}

ssize_t sock_recv(int sockfd, void *buf, size_t len)
{
	return recv(sockfd, buf, len, 0);
}
