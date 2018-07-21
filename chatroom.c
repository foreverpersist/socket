#include "sock.h"
#include "hashmap.h"
#include <stdbool.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#define MODE_SERVER 0
#define MODE_CLIENT 1

#define DEFAULT_PORT 6666
#define BUFF_SIZE 1024
#define EPOLL_MAXEVENTS 64
#define EPOLL_TIMEOUT 5000

/* ===== Server ===== */
/*         ||         */
/*         ||         */
/*         \/         */


typedef struct
{
	int fd;
	char addr[32];
	char name[32];
	int port;
} client_t, *client;

static inline size_t int_hash(int key, size_t capacity)
{
	return key;
}

HASHMAP_DEFINE(client, int, client)
HASHMAP_DEFINE(name, const char *,int)

typedef struct 
{
	hashmap(client) client_map;
	hashmap(name) name_map;
	int count;
} server_t, *server;


/* ===== Message functions ===== */

/* Send message to client specified by fd
 */
static inline int send_msg(int fd, char *msg)
{
	return sock_send(fd, msg, strlen(msg));
}

/* Send message to all clients
 */
static void send_all(server s, char *msg)
{
	iter(client) it;
	for (it = hashmap_iter(client, s->client_map); it != NULL; 
		it = hashmap_next(client, s->client_map, it))
	{
		send_msg(it->key, msg);
	}
}

/* Send message to all clients except client specified by fd
 */
static void send_others(server s, char *msg, int fd)
{
	iter(client) it;
	for (it = hashmap_iter(client, s->client_map); it != NULL; 
		it = hashmap_next(client, s->client_map, it))
	{
		if (it->key != fd)
			send_msg(it->key, msg);
	}
}

/* ===== Command functions ===== */

/* Client joins
   Send message to all clients except itself:
       <SERVER> JOIN [USER id name]
   Send message to client itself:
       <SERVER> CONNECT [USER id name]
 */
static void cmd_join(server s, int fd, struct sockaddr_in addr, char *buff)
{
	client c;
	c = (client) malloc(sizeof(client_t));
	c->fd = fd;
	sprintf(c->addr, "%d.%d.%d.%d",
		addr.sin_addr.s_addr & 0xFF,
		(addr.sin_addr.s_addr & 0xFF00)>>8,
		(addr.sin_addr.s_addr & 0xFF0000)>>16,
		(addr.sin_addr.s_addr & 0xFF000000)>>24);
	sprintf(c->name, "%d", fd);
	c->port = addr.sin_port;
	sprintf(buff, "<SERVER> JOIN [USER %d %s]\n", fd, c->name);
	send_others(s, buff, fd);
	sprintf(buff, "<SERVER> CONNECT [USER %d %s]\n", fd, c->name);
	send_msg(fd, buff);
	hashmap_put(client, s->client_map, fd, c);
	hashmap_put(name, s->name_map, c->name, fd);
	s->count++;	
}

/* Client quits
   Send message to all clients except itself:
       <SERVER> QUIT [USER id name]
   Send message to client itself:
       <SERVER> DISCONNECT [USER id name]
 */
static void cmd_quit(server s, int fd, char *buff)
{
	client c;
	hashmap_get(client, s->client_map, fd, &c);
	sprintf(buff, "<SERVER> QUIT [USER %d %s]", fd, c->name);
	send_others(s, buff, fd);
	sprintf(buff, "<SERVER> DISCONNECT [USER %d %s]", fd, c->name);
	send_msg(fd, buff);
	hashmap_remove(name, s->name_map, c->name);
	hashmap_remove(client, s->client_map, fd);
	free(c);
	s->count--;
}

/* Client queries itself information
   Send message to client:
       <SERVER> INFO
       [id]   id
       [addr] addr
       [name] name
 */
static void cmd_info(server s, int fd, char *buff)
{
	char tmp[64];
	client c;
	sprintf(buff, "<SERVER> INFO\n");
	hashmap_get(client, s->client_map, fd, &c);
	sprintf(tmp, "[id]   %d\n", c->fd);
	strcat(buff, tmp);
	sprintf(tmp, "[addr] %s\n", c->addr);
	strcat(buff, tmp);
	sprintf(tmp, "[name] %s\n", c->name);
	strcat(buff, tmp);
	sprintf(tmp, "[port] %d\n", c->port);
	strcat(buff, tmp);
	send_msg(fd, buff);
}

/* Client renames itself
   Send message to all client:
       <SERVER> RENAME [USER id] old TO new
   Or send message to client:
       <SERVER> ERROR ...
 */
static void cmd_rename(server s, int fd, char *buff, char *name)
{
	client c;
	if (name)
	{

		if (hashmap_has_key(name, s->name_map, name) == 0)
		{
			sprintf(buff, "<SERVER> ERROR NAME HAS EXISTS\n");
			send_msg(fd, buff);
		}
		else
		{
			hashmap_get(client, s->client_map, fd, &c);
			hashmap_remove(name, s->name_map, c->name);
			sprintf(buff, "<SERVER> RENAME [USER %d] %s TO %s\n", fd, c->name, name);
			send_all(s, buff);
			sprintf(c->name, "%s", name);
			hashmap_put(name, s->name_map, name, fd);
		}
	}
	else 
	{
		sprintf(buff, "<SERVER> ERROR NAME IS INVALID\n");
		send_msg(fd, buff);
	}
}

/* Client queries all online users
   Send message to client:
       <SERVER> USERS-BEGIN
       [id] id1, [name] name1
       [id] id2, [name] name2
       ...
       <SERVER> USERS-MORE
       [id] id1, [name] name1
       [id] id2, [name] name2
       ...
       <SERVER> USERS-END
 */
static void cmd_users(server s, int fd, char *buff)
{
	char tmp[64];
	int len;
	iter(client) it;
	sprintf(buff, "<SERVER> USERS-BEGIN\n");
	for (it = hashmap_iter(client, s->client_map); it != NULL; 
		it = hashmap_next(client, s->client_map, it))
	{
		len = sprintf(tmp, "[id] %d, [name] %s\n", it->key, it->value->name);
		if (strlen(buff) + len < BUFF_SIZE)
		{
			strcat(buff, tmp);
		}
		else
		{
			send_msg(fd, buff);
			sprintf(buff, "<SERVER> USERS-MORE\n");
		}
	}

	if (strlen(buff) + 18 < BUFF_SIZE)
	{
		strcat(buff, "<SERVER> USERS-END");
	}
	else
	{
		send_msg(fd, buff);
		sprintf(buff, "<SERVER> USERS-END>");
	}
	send_msg(fd, buff);
}

/* Client queries help message
   Send message to client
       <SERVER> HELP
       ...
 */
static void cmd_help(int fd, char *buff)
{
	sprintf(buff, "<SERVER> HELP\n");
	strcat(buff, ":quit                      \tquit chatroom\n");
	strcat(buff, ":info                      \tshow client info\n");
	strcat(buff, ":rename [name]             \tchange client name\n");
	strcat(buff, ":users                     \tshow all users' info\n");
	strcat(buff, ":help                      \tshow help\n");
	strcat(buff, ":private [id|name] [msg]   \tsend private message\n");
	strcat(buff, "[msg]                      \tsend public message\n");
	strcat(buff, ":file [id|name] [file]     \tsend private file\n");
	send_msg(fd, buff);
}

/* Client sends private message to the client specified by name
   Send message to specified client:
       <P>[id name] ...
 */
static void cmd_private(server s, int fd, char *buff, char *msg, char *name)
{
	client c;
	int cfd = -1;
	hashmap_get(client, s->client_map, fd, &c);
	if ((cfd = atoi(name)) <= 0)
	{
		hashmap_get(name, s->name_map, name, &cfd);
	}
	if (hashmap_has_key(client, s->client_map, cfd) == 0 && cfd != fd)
	{
		sprintf(buff, "<P>[%d %s] %s\n", fd, c->name, msg);
		send_msg(cfd, buff);
		sprintf(buff, "<SERVER> PRIVATE\n");
		send_msg(fd, buff);
	}
	else
	{
		sprintf(buff, "<SERVER> ERROR PRIVATE USER IS INVALID\n");
		send_msg(fd, buff);
	}
}

/* Client sends public message
   Send message to all client except itself:
       [id name] ...
 */
static void cmd_public(server s, int fd, char *buff, char *msg)
{
	client c;
	hashmap_get(client, s->client_map, fd, &c);
	sprintf(buff, "[%d %s] %s\n", fd, c->name, msg);
	send_others(s, buff, fd);
	sprintf(buff, "<SERVER> PUBLIC\n");
	send_msg(fd, buff);
}

/* Client sends private file
   Send message to specific client:
       <F>[id name] role peer_host peer_port local_port file [size]
 */
static void cmd_file(server s, int fd, char *buff, char *msg, char *name)
{
	client c;
	client r;
	int rfd = -1;
	char *param;
	char *file;
	long long size;
	hashmap_get(client, s->client_map, fd, &c);
	if ((rfd = atoi(name)) <= 0)
	{
		hashmap_get(name, s->name_map, name, &rfd);
	}
	if (hashmap_get(client, s->client_map, rfd, &r) == 0 && rfd != fd)
	{
		// Parse msg: file [size]
		file = strtok(msg, " \n");
		param = strtok(NULL, " \n");
		size = atoll(param);
		// Send message to sender:
		//     <F>[r_id r_name] sender r_host r_port s_port file size
		sprintf(buff, "<F>[%d %s] sender %s %d %d %s %lld\n", 
			r->fd, r->name, r->addr, r->port, c->port, file, size);
		send_msg(fd, buff);
		// Send message to receiver:
		//    <F>[s_id s_name] receiver s_host s_port r_port file size
		sprintf(buff, "<F>[%d %s] receiver %s %d %d %s %lld\n", 
			c->fd, c->name, c->addr, c->port, r->port, file, size);
		send_msg(rfd, buff);
	}
	else
	{
		sprintf(buff, "<SERVER> ERROR PRIVATE USER IS INVALID\n");
		send_msg(fd, buff);
	}
}

static int handle_message(server s, int fd, char *msg, int len)
{
	char *cmd;
	char *param;
	char *name;
	char *real_msg;
	int cfd;
	client c;
	char buff[BUFF_SIZE];

	msg[len] = 0;
	cmd = strtok(msg, " \n");
	if (cmd == NULL)
	{
		sprintf(buff, "<SERVER> ERROR EMPTY CONTENT\n");
		return 0;
	}
	if (!strcmp(cmd, ":quit") || !strcmp(cmd, ":q"))
	{
		cmd_quit(s, fd, buff);
		return -1;
	}
	else if(!strcmp(cmd, ":info") || !strcmp(cmd, ":i"))
	{
		cmd_info(s, fd, buff);
	}
	else if (!strcmp(cmd, ":rename") || !strcmp(cmd, ":r"))
	{
		param = strtok(NULL, " \n");
		cmd_rename(s, fd, buff, param);
		
	}
	else if (!strcmp(cmd, ":users") || !strcmp(cmd, ":u"))
	{
		cmd_users(s, fd, buff);
	}
	else if (!strcmp(cmd, ":help") || !strcmp(cmd, ":h"))
	{
		cmd_help(fd, buff);
	}
	else if (!strcmp(cmd, ":private") || !strcmp(cmd, ":p"))
	{
		param = strtok(NULL, " \n");
		real_msg = param + strlen(param) + 1;
		cmd_private(s, fd, buff, real_msg, param);
	}
	else if (!strcmp(cmd, ":file") || !strcmp(cmd, ":f"))
	{
		param = strtok(NULL, " \n");
		real_msg = param + strlen(param) + 1;
		cmd_file(s, fd, buff, real_msg, param);
	}
	else
	{
		cmd[strlen(cmd)] = ' ';
		cmd_public(s, fd, buff, msg);
	}

	return 0;
} 


static int start_server(int port)
{
	server_t s;
	int serverfd;
	int sessionfd;
	struct sockaddr_in cli_addr;
	socklen_t cli_len;
	char buff[BUFF_SIZE];
	int len;
	int i;
	int epfd;
	int res;
	struct epoll_event event;
	struct epoll_event events[EPOLL_MAXEVENTS];

	memset(&s, 0, sizeof(s));
	s.client_map = hashmap_create(client, 0, 0);
	hashmap_set_hash_func(client, s.client_map, int_hash);
	s.name_map = hashmap_create(name, 0, 0);
	hashmap_set_hash_func(name, s.name_map, str_hash);
	hashmap_set_compare_func(name, s.name_map, strcmp);
	hashmap_set_key_funcs(name, s.name_map, str_key_alloc, str_key_free);

	if ((serverfd = sock_server(port, NULL, 10)) < 0)
	{
		perror("sock_server");
		return -1;	
	}

	if ((epfd = epoll_create(1)) < 0)
	{
		perror("epoll_create");
		return -3;
	}

	event.events = EPOLLIN;
	event.data.fd = serverfd;
	if (epoll_ctl(epfd, EPOLL_CTL_ADD, serverfd, &event) < 0)
	{
		perror("epoll_ctl");
		return -4;
	}

	memset(events, 0, sizeof(events));

	while(1)
	{
		res = epoll_wait(epfd, events, EPOLL_MAXEVENTS, EPOLL_TIMEOUT);

		if (res == -1)
		{
			perror("epoll_wait");
			return -5;
		}
		else if (res == 0)
		{
			continue;
		}

		for (i = 0; i < res; i++)
		{

			if (events[i].data.fd == serverfd)
			{
				cli_len = sizeof(cli_addr);
				if ((sessionfd = sock_accept(serverfd, (struct sockaddr *) &cli_addr, 
					&cli_len)) < 0)
				{
					perror("sock_accept");
					return -6;
				}

				cmd_join(&s, sessionfd, cli_addr, buff);

				event.events = EPOLLIN;
				event.data.fd = sessionfd;
				if (epoll_ctl(epfd, EPOLL_CTL_ADD, sessionfd, &event))
				{
					perror("epoll_ctl");
					return -4;
				}
			}
			else if (events[i].events & EPOLLIN)
			{
				sessionfd = events[i].data.fd;
				if (sessionfd < 0)
					continue;

				if (((len = sock_recv(sessionfd, buff, BUFF_SIZE)) <= 0) 
					|| (handle_message(&s, sessionfd, buff, len) < 0))
				{
					close(sessionfd);
				}
			}
		}
	}

	hashmap_destroy(client, s.client_map);
	hashmap_destroy(name, s.name_map);

	return 0;
}

/*         /\         */
/*         ||         */
/*         ||         */
/* ===== Server ===== */


/* ===== Client ===== */
/*         ||         */
/*         ||         */
/*         \/         */

#define NONE                 "\e[0m"
#define BLACK                "\e[0;30m"
#define L_BLACK              "\e[1;30m"
#define RED                  "\e[0;31m"
#define L_RED                "\e[1;31m"
#define GREEN                "\e[0;32m"
#define L_GREEN              "\e[1;32m"
#define BROWN                "\e[0;33m"
#define YELLOW               "\e[1;33m"
#define BLUE                 "\e[0;34m"
#define L_BLUE               "\e[1;34m"
#define PURPLE               "\e[0;35m"
#define L_PURPLE             "\e[1;35m"
#define CYAN                 "\e[0;36m"
#define L_CYAN               "\e[1;36m"
#define GRAY                 "\e[0;37m"
#define WHITE                "\e[1;37m"

typedef struct 
{
	int fd;
	int id;
	char name[32];
	char addr[32];
	char dir[512];
	int port;
	volatile bool alive;
} conn_t, *conn;


static void inline show_time()
{
	time_t raw;
	struct tm *info;
	time(&raw);
	info = localtime(&raw);
	printf(WHITE "%s" NONE, asctime(info));
}

/* Client connects
 */
static void show_connect(conn c, int id, char *name)
{
	show_time();
	printf(GREEN "CONNECT TO SERVER,  [id] %d, [name] %s \n\n" NONE, id, name);
}

/* Client disconnects
 */
static void show_disconnect(conn c, int id, char *name)
{
	show_time();
	printf(GREEN "DISCONNECT TO SERVER\n\n" NONE);
}

/* One user joins
 */
static void show_join(int id, char *name)
{
	show_time();
	printf(GREEN "A USER JOINS, [id] %d [name] %s\n\n" NONE, id, name);
}

/* One user quits
 */
static void show_quit(int id, char *name)
{
	show_time();
	printf(GREEN "A USER QUITS, [id] %d [name] %s\n\n" NONE, id, name);
}

/* Clients gets info about itself
 */
static void show_info(int id, char *name, char *addr, int port)
{
	show_time();
	printf(GREEN "CURRENT INFO, [id] %d [name] %s [addr] %s [port] %d\n\n" NONE, id, name, addr, port);
}

/* Clients renames itself
 */
static void show_rename(int id, char *old, char *new)
{
	show_time();
	printf(GREEN "RENAME, [old] %s [new] %s\n\n" NONE, old, new);
}

/* Clients gets error message
 */
static void show_error(char *msg)
{
	show_time();
	printf(RED "ERROR, %s\n" NONE, msg);
}

/* Client gets info about all others [begin]
 */
static void show_users_begin()
{
	show_time();
	printf(GREEN "ALL USERS\n" NONE);
	printf("================================\n");
	printf("id\tname\n");
}

/* Client gets info about all others
 */
static void show_user(int id, char *name)
{
	printf(GREEN"%-5d\t%s\n" NONE, id, name);
}

/* Client gets info about all others [end]
 */
static void show_users_end()
{
	printf("================================\n\n");
}

/* Client sends private message
 */
static void show_private()
{
	show_time();
	printf(GREEN "PRIVATE MESSAGE HAS BEEN SENT\n\n" NONE);
}

/* Client sends public message
 */
static void show_public()
{
	show_time();
	printf(GREEN "MESSAGE HAS BEEN SENT\n\n" NONE);
}

/* Client gets help message
 */
static void show_help(char *msg)
{
	show_time();
	printf(GREEN "HELP\n" NONE);
	printf(GREEN "%s\n" NONE, msg);
}

/* Client gets unknown message
 */
static void show_unknown(char *msg)
{
	show_time();
	printf(YELLOW "UNKNOWN\n%s\n" NONE, msg);
}

/* Client gets private message from one user
 */
static void show_msg_private(int id, char *name, char *msg)
{
	show_time();
	printf(PURPLE "<P>[%d][%s]: \n" NONE, id, name);
	printf("%s\n", msg);
}

/* Client gets public message from one user
 */
static void show_msg_public(int id, char *name, char *msg)
{
	show_time();
	printf(CYAN "[%d][%s]: \n" NONE, id, name);
	printf("%s\n", msg);
}

typedef enum 
{
	STATE_UNKNOWN,
	STATE_SERVER,
	STATE_CLIENT,
	STATE_ERROR,
	STATE_SUCCESS
} peer_state;

typedef struct
{
	bool sender;
	char *peer_host;
	int peer_port;
	int local_port;
	char *dir;
	char *file;
	long long size;
	long long real_size;
	volatile peer_state state;
	pthread_mutex_t lock;
} peer_conn_t, *peer_conn;

static int tranfer_file(int fd, peer_conn pc)
{
	FILE *fp;
	char *filename;
	char *filepath;
	int len;
	char buff[BUFF_SIZE];
	int ret = -1;
	long long size = 0;

	if (pc->sender)
	{
		if ((fp = fopen(pc->file, "r")) != NULL)
		{
			while ((len = fread(buff, sizeof(char), BUFF_SIZE, fp)) > 0)
			{
				if ((len = sock_send(fd, buff, len)) <= 0)
				{
					printf("FAIL TO SEND FILE\n");
					break;
				}
				size += len;
				// printf("HAVE SENT %lld B\n", size);
			}
			pc->real_size = size;
			fclose(fp);
			close(fd);
			ret = 0;
		}
		else
		{
			printf("CAN NOT OPEN FILE %s\n", pc->file);
		}
	}
	else 
	{
		if ( (filename = strrchr(pc->file, '/')) != NULL)
			filename += 1;
		else
			filename = pc->file;
		filepath = malloc(sizeof(char) * (strlen(pc->dir) + 3 + strlen(filename)));
		sprintf(filepath, "%s/%s", pc->dir, filename);
		if ((fp = fopen(filepath, "w")) != NULL)
		{
			while ((len = sock_recv(fd, buff, BUFF_SIZE)) > 0)
			{
				if ((len = fwrite(buff, sizeof(char), len, fp)) <= 0)
				{
					printf("FAIL TO SAVE FILE\n");
					break;
				}
				size += len;
			}
			pc->real_size = size;
			close(fd);
			fclose(fp);
			ret = 0;
		}
		else
		{
			printf("CAN NOT OPEN FILE %s\n", filepath);
		}
		free(filepath);
	}

	return ret;
}

static void *peer_server(void *arg)
{
	peer_conn pc;
	struct sockaddr_in addr;
	socklen_t slen;
	int serverfd;
	int sessionfd;
	int value = 1;
	int flag;

	pc = (peer_conn) arg;

	if ((serverfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		return NULL;
	}
	if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0)
	{
		return NULL;
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(pc->local_port);

	if (bind(serverfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
	{
		return NULL;
	}

	if (listen(serverfd, 5) < 0)
	{
		return NULL;
	}

	flag = fcntl(serverfd, F_GETFL, 0);
	fcntl(serverfd, F_SETFL, flag | O_NONBLOCK);

	slen = sizeof(addr);
	while (pc->state == STATE_UNKNOWN)
	{
		if ((sessionfd = accept(serverfd, (struct sockaddr *)&addr, &slen)) > 0)
		{
			pthread_mutex_lock(&pc->lock);
			if (pc->state == STATE_CLIENT)
			{
				pthread_mutex_unlock(&pc->lock);
				close(sessionfd);
				break;
			}
			pc->state = STATE_SERVER;
			pthread_mutex_unlock(&pc->lock);

			flag = fcntl(serverfd, F_GETFL, 0);
			fcntl(serverfd, F_SETFL, flag | ~O_NONBLOCK);

			// Transfer file
			if (tranfer_file(sessionfd, pc) == 0)
			{
				pc->state = STATE_SUCCESS;
			}
			else
			{
				pc->state = STATE_ERROR;
			}
		}
	}
	close(serverfd);

	return NULL;
}

static void *peer_client(void *arg)
{
	peer_conn pc;
	struct sockaddr_in addr;
	int clientfd;
	int value = 1;
	int flag;

	pc = (peer_conn) arg;

	if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		return NULL;
	}
	if (setsockopt(clientfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) < 0)
	{
		return NULL;
	}

	addr.sin_family = AF_INET;
	inet_pton(AF_INET, pc->peer_host, &addr.sin_addr);
	addr.sin_port = htons(pc->peer_port);

	flag = fcntl(clientfd, F_GETFL, 0);
	fcntl(clientfd, F_SETFL, flag | O_NONBLOCK);

	while (pc->state == STATE_UNKNOWN)
	{
		if (connect(clientfd, (struct sockaddr *)&addr, sizeof(addr)) == 0)
		{
			pthread_mutex_lock(&pc->lock);
			if (pc->state == STATE_SERVER)
			{
				pthread_mutex_unlock(&pc->lock);
				close(clientfd);
				break;
			}
			pc->state = STATE_CLIENT;
			pthread_mutex_unlock(&pc->lock);

			flag = fcntl(clientfd, F_GETFL, 0);
			fcntl(clientfd, F_SETFL, flag | ~O_NONBLOCK);

			// Transfer file
			if (tranfer_file(clientfd, pc) == 0)
			{
				pc->state = STATE_SUCCESS;
			}
			else
			{
				pc->state = STATE_ERROR;
			}
		}
	}

	return NULL;
}

static char *format_file_size(long long size)
{
	char *buff;
	const char suffixes[5] = {'B', 'K', 'M', 'G', 'T'};
	int values[5];
	int i = 0;
	long long cur = size;
	float v;

	buff = malloc(sizeof(char) * 64);
	while (i < 4 && cur > 0)
	{
		values[i++] = cur % 1024;
		cur /= 1024;
	}
	if (cur > 0)
	{
		values[i++] = cur;
	}
	i--;

	v = values[i];
	if (i > 0)
		v += 1.0f * values[i - 1] / 1024;

	sprintf(buff, "%.2f %c", v ,suffixes[i]);

	return buff;
}

/* Client gets file messge from one user
   msg format: role peer_host peer_port local_port file [size]
       role: s[ender], r[eceiver]
 */
static void show_msg_file(int id, char *name, char *msg, int msg_len, conn c)
{
	peer_conn pc;
	char *param;
	pthread_t st, ct;

	if ((pc = malloc(sizeof(peer_conn_t))) == NULL)
	{
		show_time();
		printf(RED "ERROR, FAIL TO ALLOCATE MEMORY\n" NONE);
		return;
	}

	// Parse message
	param = strtok(msg, " ");
	if (!strcmp(param, "s") || !strcmp(param, "sender"))
	{
		pc->sender = true;
	}
	else if (!strcmp(param, "r") || !strcmp(param, "receiver"))
	{
		pc->sender = false;
	}
	else
	{
		show_time();
		printf(RED "ERROR, UNKNOWN FILE TRANSFER ROLE: %s\n" NONE, param);
		return;
	}
	param = strtok(NULL, " ");
	pc->peer_host = strdup(param);
	param = strtok(NULL, " ");
	pc->peer_port = atoi(param);
	param = strtok(NULL, " ");
	pc->local_port = atoi(param);
	param = strtok(NULL, " ");
	pc->dir = strdup(c->dir);
	pc->file = strdup(param);
	param = strtok(NULL, " ");
	pc->size = atoll(param);
	pc->state = STATE_UNKNOWN;
	pthread_mutex_init(&pc->lock, NULL);

	// Create peer connection, then transfer file
	pthread_create(&st, NULL, peer_server, pc);
	pthread_create(&ct, NULL, peer_client, pc);
	pthread_join(st, NULL);
	pthread_join(ct, NULL);

	show_time();
	printf(PURPLE "<F>[%d][%s]: \n" NONE, id, name);
	if (pc->state == STATE_SUCCESS)
	{
		if (pc->sender)
			printf(PURPLE "SUCCESS, FILE HAS BEEN SENT\n" NONE);
		else
			printf(PURPLE "SUCCESS, FILE HAS BEEN SAVED AT %s\n" NONE, pc->dir);
		printf(PURPLE "FILE: %s\n" NONE, pc->file);
		param = format_file_size(pc->real_size);
		printf(PURPLE "SIZE: %s [%lld]\n\n" NONE, param, pc->real_size);
		free(param);
	}
	else
	{
		if (pc->sender)
			printf(RED "ERROR, FAIL TO SEND FILE %s\n\n" NONE, pc->file);
		else
			printf(RED "ERROR, FAIL TO RECEIVE FILE %s\n\n" NONE, pc->file);
	}

	free(pc->peer_host);
	free(pc->dir);
	free(pc->file);
	pthread_mutex_destroy(&pc->lock);
	free(pc);
}

/* Client gets message from unknown user
 */
static void show_msg_unknown(char *msg)
{
	show_time();
	printf(YELLOW "[UNKNOWN]: \n" NONE);
	printf("%s\n", msg);
}

static void *client_worker(void *arg)
{
	char *who;
	char *param;
	int id;
	char name[32];
	char addr[32];
	conn c;
	char buff[BUFF_SIZE];
	int len;
	char tag[32];

	c = (conn) arg;

	while (c->alive && (len = sock_recv(c->fd, buff, BUFF_SIZE)) > 0)
	{
		buff[len] = 0;
		who = strtok(buff, " ");
		if (who == NULL)
			continue;
		if (!strcmp(who, "<SERVER>"))
		{
			/* Message comes from server */
			param = strtok(NULL, " \n");
			if (!strcmp(param, "CONNECT"))
			{
				param += 8;
				sscanf(param, "[USER %d %s]", &id, name);
				name[strlen(name)-1] = 0;
				strcpy(c->name, name);
				show_connect(c, id, name);
			}
			else if (!strcmp(param, "DISCONNECT"))
			{
				param += 11;
				sscanf(param, "[USER %d %s]", &id, name);
				name[strlen(name)-1] = 0;
				show_disconnect(c, id, name);
				c->alive = false;
				printf(GREEN"PRESS ANY KEY TO EXIT\n" NONE);
				break;
			}
			else if (!strcmp(param, "JOIN"))
			{
				param += 5;
				sscanf(param, "[USER %d %s]", &id, name);
				name[strlen(name)-1] = 0;
				show_join(id, name);
			}
			else if (!strcmp(param, "QUIT"))
			{
				param += 5;
				sscanf(param, "[USER %d %s]", &id, name);
				name[strlen(name)-1] = 0;
				show_quit(id, name);
			}
			else if (!strcmp(param, "INFO"))
			{
				param = strtok(NULL, "\n");
				sscanf(param, "%s %d", tag, &id);
				param = strtok(NULL, "\n");
				sscanf(param, "%s %s", tag, addr);
				param = strtok(NULL, "\n");
				sscanf(param, "%s %s", tag, name);
				param = strtok(NULL, "\n");
				sscanf(param, "%s %d", tag, &(c->port));
				show_info(id, name, addr, c->port);
			}
			else if (!strcmp(param, "RENAME"))
			{
				param += 7;
				sscanf(param, "[USER %d] %s TO %s", &id, tag, name);
				strcpy(c->name, name);
				show_rename(id, tag, name);
			}
			else if (!strcmp(param, "ERROR"))
			{
				param = param + 6;
				show_error(param);
			}
			else if (!strcmp(param, "USERS-BEGIN"))
			{
				show_users_begin();
				while (param = strtok(NULL, "\n"))
				{
					if (!strcmp(param, "<SERVER> USERS-END"))
					{
						show_users_end();
						break;
					}
					sscanf(param, "[id] %d, [name] %s", &id, name);
					show_user(id, name);
				}
			}
			else if (!strcmp(param, "USERS-MORE"))
			{
				while (param = strtok(NULL, "\n"))
				{
					if (!strcmp(param, "<SERVER> USERS-END"))
					{
						show_users_end();
						break;
					}
					sscanf(param, "[id] %d, [name] %s", &id, name);
					show_user(id, name);
				}
			}
			else if (!strcmp(param, "USERS-END"))
			{
				show_users_end();
			}
			else if (!strcmp(param, "HELP"))
			{
				param += 5;
				show_help(param);
			}
			else if (!strcmp(param, "PRIVATE"))
                        {
                                show_private();
                        }
                        else if (!strcmp(param, "PUBLIC"))
                        {
                                show_public();
                        }
			else
			{
				/* Unkown type */
				param[strlen(param)] = ' ';
				show_unknown(param);
			}
		}
		else if (!strncmp(who, "<P>[", 4))
		{
			/* Private message comes from client */
			sscanf(who, "<P>[%d", &id);
			param = strtok(NULL, " ");
			strcpy(name, param);
			name[strlen(name)-1] = 0;
			param += strlen(param) + 1;
			show_msg_private(id, name, param);
		}
		else if (who[0] == '[')
		{
			/* Message comes from client */
			sscanf(who, "[%d", &id);
			param = strtok(NULL, " ");
			strcpy(name, param);
			name[strlen(name)-1] = 0;
			param += strlen(param) + 1;
			show_msg_public(id, name, param);
		}
		else if(!strncmp(who, "<F>[", 4))
		{
			/* File message come from client */
			sscanf(who, "<F>[%d", &id);
			param = strtok(NULL, " ");
			strcpy(name, param);
			name[strlen(name)-1] = 0;
			param += strlen(param) + 1;
			show_msg_file(id, name, param, len - (buff - param), c);
		}
		else
		{
			/* Message comes from unknown source */
			who[strlen(who)] = ' ';
			param = who;
			show_msg_unknown(param);
		}
	}

	return NULL;
}

static int start_client(char *ip, int port, char *dir)
{
	conn_t c;
	int clientfd;
	char buff[BUFF_SIZE];
	int len;
	pthread_t tid;
	char cmd[64];
	char name[64];
	char filepath[1024];
	struct stat stat_buff;

	memset(&c, 0, sizeof(c));

	if ((clientfd = sock_client(ip, port, NULL)) < 0)
	{
		perror("sock_client");
		return -1;
	}

	c.fd = clientfd;
	c.alive = true;
	strcpy(c.dir, dir);
	/* Receive messages from server */
	pthread_create(&tid, NULL, client_worker, (void *) &c);

	/* Send messages to server */
	while (c.alive)
	{
		fgets(buff, BUFF_SIZE, stdin);
		len = strlen(buff);
		buff[len] = 0;

		if (!strncmp(buff, ":file ", 6) || !strncmp(buff, ":f ", 3))
		{
			// Send file
			sscanf(buff, "%s %s %s", cmd, name, filepath);
			if (!stat(filepath, &stat_buff))
			{
				// Check file and append size
				len = sprintf(buff, "%s %s %s %ld\n", cmd, name, filepath, stat_buff.st_size);
			}
			else
			{
				printf(RED "CAN NOT OPEN FILE %s\n\n" NONE, filepath);
				continue;
			}
		}

		if ((len = sock_send(clientfd, buff, len)) < 0)
			break;
	}

	pthread_join(tid, NULL);

	return 0;

}

/*         /\         */
/*         ||         */
/*         ||         */
/* ===== Client ===== */

static void usage(const char *prog)
{
	printf("Usage: %s [option]\n", prog);
	printf("    -i <ip>       server ip address\n");
	printf("    -p <port>     server port\n");
	printf("    -s            server mode\n");
	printf("    -c            client mode\n");
	printf("    -d            directory to save files\n");
	printf("    -h            help messages\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int mode = MODE_SERVER;
	char *ip = "127.0.0.1";
	int port = 6666;
	char *dir = "./";

	while ((opt = getopt(argc, argv, "i:p:scd:h")) != -1)
	{
		switch(opt)
		{
			case 'i':
				ip = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 's':
				mode = MODE_SERVER;
				break;
			case 'c':
				mode = MODE_CLIENT;
				break;
			case 'd':
				dir = optarg;
				break;
			case 'h':
				usage(argv[0]);
				return 1;
		}
	}

	if (mode == MODE_SERVER)
	{
		return start_server(port);
	}
	else if (mode == MODE_CLIENT)
	{
		return start_client(ip, port, dir);
	}
	else
	{
		fprintf(stderr, "[Error]: Unkown mode\n");
		return -1;
	}

}
