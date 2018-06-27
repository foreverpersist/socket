#include "sock.h"
#include "hashmap.h"
#include <stdbool.h>
#include <sys/epoll.h>
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
       <F>[id name] ...
 */
static void cmd_file(server s, int fd, char *buff, char *msg, char *name)
{
	client c;
	int cfd = -1;
	int header_len;
	hashmap_get(client, s->client_map, fd, &c);
	if ((cfd = atoi(name)) <= 0)
	{
		hashmap_get(name, s->name_map, name, &cfd);
	}
	if (hashmap_has_key(client, s->client_map, cfd) == 0 && cfd != fd)
	{
		header_len = sprintf(buff, "<F>[%d %s] ", fd, c->name);
		memcpy(buff + header_len, msg, BUFF_SIZE - header_len);
		sock_send(cfd, buff, BUFF_SIZE);
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
static void show_info(conn c, int id, char *name, char *addr)
{
	show_time();
	printf(GREEN "CURRENT INFO, [id] %d [name] %s [addr] %s\n\n" NONE, id, name, addr);
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

/* Client gets file messge from one user
   msg format: type length value
       type: [n]ame, [b]egin, [m]ore, [e]nd, o[k]
 */
static void show_msg_file(int id, char *name, char *msg, int msg_len, conn c)
{
	static char *filename = NULL;
	static FILE *fp = NULL;
	char *filepath;

	char *param;
	char *type;
	int len;
	char *value;
	char buff[128];

	type = strtok(msg, " ");
	param = strtok(NULL, " ");
	len = atoi(param);
	value = param + strlen(param) + 1;
	if (!strcmp(type, "name") || !strcmp(type, "n"))
	{
		value[len] = 0;
		filename = strdup(value);
		// Show filename
		show_time();
		printf(BLUE "<F>[%d %s]: \n" NONE, id, name);
		printf(L_BLUE "File <%s>\n\n" NONE, filename);
	}
	else if (!strcmp(type, "begin") || !strcmp(type, "b"))
	{
		filepath = malloc(sizeof(char) * (strlen(c->dir) + 3 + strlen(filename)));
		sprintf(filepath, "%s/%s", c->dir, filename);
		if ((fp = fopen(filepath, "w")) != NULL)
			fwrite(value, sizeof(char), len, fp);
		free(filepath);
	}
	else if (!strcmp(type, "more") || !strcmp(type, "m"))
	{
		if (fp)
			fwrite(value, sizeof(char), len, fp);
	}
	else if (!strcmp(type, "end") || !strcmp(type, "e"))
	{
		if (fp)
		{
			// fwrite(value, sizeof(char), len, fp);
			fclose(fp);
			fp = NULL;
			sprintf(buff, ":f %d o %4d %s", id, (int) strlen(filename), filename);
			sock_send(c->fd, buff, BUFF_SIZE);
			// Show file saved
			show_time();
			printf(L_BLUE "File <%s> has been saved at <%s>\n\n" NONE, filename, c->dir);
		}
		if (filename)
		{
			free(filename);
			filename = NULL;
		}
	}
	else if (!strcmp(type, "ok") || !strcmp(type, "o"))
	{
		value[len] = 0;
		printf(GREEN "FILE <%s> HAS BEEN SENT\n\n", value);
	}
	else
	{
		// Unknown type
		type[strlen(type)] = ' ';
		param[strlen(param)] = ' ';
		printf(YELLOW "<F>[%d %s][UNKNOWN]: \n" NONE, id, name);
		printf("%s\n", msg);
	}
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
				show_info(c, id, name, addr);
			}
			else if (!strcmp(param, "RENAME"))
			{
				param += 7;
				sscanf(param, "[USER %d] %s TO %s", &id, tag, name);
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
	char *filename;
	FILE *fp;
	int header_len;
	int buff_size;

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
			if ((fp = fopen(filepath, "r")) != NULL )
			{
				if ( (filename = strrchr(filepath, '/')) != NULL)
					filename += 1;
				else
					filename = filepath;
				header_len = (int) sprintf(buff, ":f %s n %4d ", name, (int) strlen(filename));
				buff_size = BUFF_SIZE - header_len - 64;
				// Send type name
				len = sprintf(buff + header_len, "%s", filename);
				if ((len = sock_send(clientfd, buff, BUFF_SIZE)) < 0)
					break;
				// Send type begin
				len = fread(buff+header_len, sizeof(char), buff_size, fp);
				sprintf(buff + header_len - 7, "b %4d", len);
				buff[header_len - 1] = ' ';
				if ((len = sock_send(clientfd, buff, BUFF_SIZE)) < 0)
					break;
				while ((len = fread(buff+header_len, sizeof(char), buff_size, fp)) > 0)
				{
					// Send type more
					sprintf(buff + header_len - 7, "m %4d", len);
					buff[header_len - 1] = ' ';
					if ((len = sock_send(clientfd, buff, BUFF_SIZE)) < 0)
					{
						break;
					}
				}
				// Send type end
				sprintf(buff + header_len - 7, "e    0 \n");
				if (len < 0 || ((len = sock_send(clientfd, buff, BUFF_SIZE)) < 0))
					break;
			}
			else
			{
				printf(RED "CAN NOT OPEN FILE %s\n\n" NONE, filename);
			}
			continue;
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
