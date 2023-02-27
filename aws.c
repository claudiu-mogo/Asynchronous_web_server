#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include "aws.h"
#include <string.h>
#include "w_epoll.h"
#include "http_parser.h"
#include <assert.h>
#include "sock_util.h"
#include <libaio.h>
#include "util.h"

/* just a return value */
int ret;

static http_parser request_parser;
/* in request path we will store the path to the file */
char *request_path;

/* in add_to_header we will add the required header + the Content Length */
char add_to_header[10000] = "";
char header[10000] = "HTTP/1.1 200 OK\r\n"
"Date: Data de azi\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n";

char bad_header[10000] = "HTTP/1.1 404 Not Found\r\n"
"Date: Data de azi\r\n"
"Connection: close\r\n"
"Content-Type: text/html\r\n";

typedef struct connection {
    /* file descriptor in itself */
    int connection_fd;
    /* closed or open */
    int state;
    /* buffer for received bytes */
    char receive_buffer[10000];
    int receive_buffer_length;
    /* number of bytes sent by "send" */
    int sent_so_far;
    
    /* file goodies */
    char *path_to_file;
    int file_descriptor;
    struct stat *file_stats;
    /* number of bytes sent by "sendfile" */
    int written_bytes;
} Connect;

static int on_path_cb(http_parser *p, const char *buf, long unsigned int len)
{
	assert(p == &request_parser);
	memcpy(request_path, buf, len);

	return 0;
}

/* Use mostly null settings except for on_path callback. */
static http_parser_settings settings_on_path = {
	/* on_message_begin */ 0,
	/* on_header_field */ 0,
	/* on_header_value */ 0,
	/* on_path */ on_path_cb,
	/* on_url */ 0,
	/* on_fragment */ 0,
	/* on_query_string */ 0,
	/* on_body */ 0,
	/* on_headers_complete */ 0,
	/* on_message_complete */ 0
};

Connect *create_structure(int epoll_object, int connection_fd)
{
    /* handle client request, create connection structure and add to epoll */
    Connect *conn = malloc(sizeof(Connect));
    conn->connection_fd = connection_fd;
    conn->state = 1;
    conn->file_stats = NULL;
    memset(conn->receive_buffer, 0, 10000);
    conn->receive_buffer_length = 0;
    conn->written_bytes = 0;
    
    /* make socket nonblock */
    int old_flags = fcntl(conn->connection_fd, F_GETFL);
    fcntl(conn->connection_fd, F_SETFL, old_flags | O_NONBLOCK);

    w_epoll_add_ptr_in(epoll_object, conn->connection_fd, conn);
    return conn;
}

void parse_http(Connect *conn)
{
    /* parse http */
    memset(request_path, 0, 10000);
    http_parser_init(&request_parser, HTTP_REQUEST);
    int bytes = 0;
    bytes = http_parser_execute(&request_parser, &settings_on_path, conn->receive_buffer, conn->receive_buffer_length);
    /* generate the path to the file */
    conn->path_to_file = calloc(10000, sizeof(char));
    conn->sent_so_far = 0;
    strcpy(conn->path_to_file, AWS_DOCUMENT_ROOT);
    strcat(conn->path_to_file, request_path + 1);

    /* open file */
    conn->file_descriptor = open(conn->path_to_file, O_RDONLY | O_NONBLOCK);
}

void memory_release(Connect *conn)
{
    close(conn->connection_fd);
    close(conn->file_descriptor);
    free(conn->file_stats);
    free(conn->path_to_file);
    free(conn);
}

int main()
{
    /* make a socket nonblock */
    int listenfd = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    /* epoll descriptor */
    int epoll_object = epoll_create(1);
    struct epoll_event epl_event;

    /* zero-ize the path to the file for safety */
    request_path = calloc(10000, sizeof(char));

    /* create listener and add to epoll -- already has DIEs internally */
    listenfd = tcp_create_listener(AWS_LISTEN_PORT, DEFAULT_LISTEN_BACKLOG);
    w_epoll_add_fd_in(epoll_object, listenfd);
    struct epoll_event ret_ev;
    
    /* server loop */
    while (1) {
        /* wait for an event */
        ret = epoll_wait(epoll_object, &ret_ev, 1, -1);
        DIE(ret < 0, "epoll_wait error");
        /* if we want to initiate a connection */
        if ((ret_ev.data.fd == listenfd) && ((ret_ev.events & EPOLLIN) != 0)) {
            socklen_t addrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in addr;
            int connection_fd = accept(listenfd, (struct sockaddr *) &addr, &addrlen);
            DIE(connection_fd < 0, "wrong accept");

            if (connection_fd > 0) {
                Connect *conn = create_structure(epoll_object, connection_fd);
            }
        } else {
            /* check for input from epoll */
            if ((ret_ev.events & EPOLLIN) != 0) {

                /* append to receive_buffer */
                Connect *conn = ret_ev.data.ptr;
                int bytes = 0;
                bytes = recv(conn->connection_fd, conn->receive_buffer + conn->receive_buffer_length, 10000, 0);
                DIE(bytes <= 0, "receive stopped unexpectedly");
                conn->receive_buffer_length += bytes;

                /* if the http call has ended (it will end in \r\n\r\n) */
                if (strstr(conn->receive_buffer, "\r\n\r\n")) {
                    conn->state = 0;

                    parse_http(conn);

                    /* check bad file, add the Content-Length to header and move to EPOLL_OUT */
                    if (conn->file_descriptor > 0) {
                        if (strstr(conn->path_to_file, "dyn")) {
                            io_submit(0,0,0);
                        }
                        conn->file_stats = malloc(sizeof(struct stat));
                        ret = fstat(conn->file_descriptor, conn->file_stats);
                        DIE(ret < 0, "fstat error");
                        sprintf(add_to_header, "%sContent-Length: %ld\r\n\r\n", header, conn->file_stats->st_size);
                        w_epoll_update_ptr_out(epoll_object, conn->connection_fd, conn);
                    } else {
                        sprintf(add_to_header, "%sContent-Length: %d\r\n\r\n", bad_header, 0);
                        w_epoll_update_ptr_out(epoll_object, conn->connection_fd, conn);
                    }
                }
            }

            /* output actions */
            if ((ret_ev.events & EPOLLOUT) != 0) {
                Connect *conn = ret_ev.data.ptr;
                int bytes = 0;
                /* send the header regardless of the type of the connection */
                if (conn->sent_so_far < strlen(add_to_header)) {
                    bytes = send(conn->connection_fd, add_to_header + conn->sent_so_far, strlen(add_to_header) - conn->sent_so_far, 0);
                    DIE(bytes <= 0, "send error");
                    conn->sent_so_far += bytes;
                }

                /* 404 bad file case */
                if (conn->sent_so_far == strlen(add_to_header) && conn->file_stats == NULL) {
                    w_epoll_remove_ptr(epoll_object, conn->connection_fd, conn);
                    close(conn->connection_fd);
                    free(conn);
                }

                /* if the whole header has been sent */
                if (conn->sent_so_far == strlen(add_to_header) && conn->file_stats != NULL) {
                    
                    /* send until EOF */
                    if (conn->written_bytes < conn->file_stats->st_size) {
                        /* NULL for default behaviour of sendfile */
                        conn->written_bytes += sendfile(conn->connection_fd, conn->file_descriptor, NULL, conn->file_stats->st_size);
                        DIE(conn->written_bytes < 0, "initial sendfile error");
                    }
                    if (conn->written_bytes >= conn->file_stats->st_size) {
                        /* we've sent all that had to be sent and we remove the socket from epoll */
                        w_epoll_remove_ptr(epoll_object, conn->connection_fd, conn);
                        /* memory release */
                        memory_release(conn);
                    }
                        
                }
                    
            }
            
        }
    }
}