# SOCKET

	Simple INET/UNIX Socket API

## API

	Create server

> * Create an INET server if port is valid. Otherwise, create an UNIX server with sockfile.
> * `queue_length` is the length of connection waitting queue.
> * Return server fd for success, negative value for failure.

```
	int sock_server(int port, const char *sockfile, int queue_length);
```

---

	Accept a client and create a session.

> * You can set `addr=NULL`, `addrlen=NULL` to ignore client info.
> * Return sessionfd for success, negative value for failure

```
	int sock_accept(int serverfd, struct sockaddr *addr, socklen_t *addrlen);
```

---

	 Create a client connected to a server
	
> * Create an INET client If host and port are valid. Otherwise, create an UNIX client.
  	> * Return client fd for success, negative value for failure.

```
	int sock_client(const char *host, int port, const char *sockfile);
```

---

	Close a server/client/session

```
	void sock_close(int fd);
```

---

	Send message

> * Return message length sent for success, negative value for failure.

```
	ssize_t sock_send(int sockfd, const void *buf, size_t len);
```

---
	
	Receive message

> * Return message length received for success, negative value for failure.
```
	ssize_t sock_recv(int sockfd, void *buf, size_t len);
```

## Example

	A Simple Chatroom Demo

[chatroom.c](chatroom.c)


### Usage

	Start server
	Default port is 6666, use option `-p` to change it.

``` bash
$ ./chatroom -s [-p PORT]
```

	Start Client
	Default server ip is 127.0.0.1, use option `-i` to change it , domain name like `localhost` is also supported.
	Default port is 6666, use option `-p` to change it.

``` bash
$ ./chatroom -c [-i IP] [-p PORT]
```

### Client commands

	Some client commands is supported when sending message.


|         COMMAND           |     DESCRIPTION      |
| ------------------------- | -------------------- |
| :quit                     | Quit                 |
| :q                        |                      |
| :info                     | Get client info      |
| :i                        |                      |
| :renmae [name]            | Rename client        |
| :r [name]                 |                      |
| :users                    | Get all users info   |
| :u                        |                      |
| :help                     | Get help message     |
| :h                        |                      |
| :private [id\|name] [msg] | Send private message |
| :p [id\|name] [msg]       |                      |
| [msg]                     | Send public message  |
| :file [id\|name] [file]   | Send private file    |
| :f [id\|name] [file]      |                      |

