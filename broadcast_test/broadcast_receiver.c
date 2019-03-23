#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

struct broadcast_info {
    unsigned short port;     
    int sd;                 
    struct sockaddr_in addr; 
};

#define MAXRECVSTRING 255 

static int
broadcast_receive(struct broadcast_info *info)
{
    char recv_msg[MAXRECVSTRING+1];
    int recv_msglen = 0;

    recv_msglen = recvfrom(info->sd, recv_msg, MAXRECVSTRING, 0, NULL, 0);
    if(recv_msglen < 0){
        printf("Failed to receive message.\n");
        return -1;
    }

    recv_msg[recv_msglen] = '\0';
    printf("Received: %s\n", recv_msg);   

    return 0;
}
 
static int
socket_initialize(struct broadcast_info *info)
{
    int rc = 0;

    info->sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(info->sd < 0){
        perror("socket");
        return -1;
    }

    info->addr.sin_family = AF_INET;
    info->addr.sin_addr.s_addr = htonl(INADDR_ANY);
    info->addr.sin_port = htons(info->port);

    rc = bind(info->sd, (struct sockaddr *)&(info->addr),
              sizeof(info->addr));
    if(info->sd < 0){
        perror("bind");
        return -1;
    }

    return 0;
}

static void
socket_finalize(struct broadcast_info *info)
{
    if(info->sd != 0){
        close(info->sd);
    }

    return;
}

static int
broadcast_receiver(struct broadcast_info *info)
{
    int rc = 0;

    rc = socket_initialize(info);
    if(rc != 0){
        return -1;
    }

    rc = broadcast_receive(info);

    socket_finalize(info);

    return 0;
}

static int
initialize(int argc, char *argv[],struct broadcast_info *info)
{
    if(argc != 2){
        printf("Usage: <port>");
        return -1;
    }

    memset(info, 0, sizeof(struct broadcast_info));
    info->port = atoi(argv[1]);

    return 0;
}

int
main(int argc, char *argv[])
{
    int rc = 0;
    struct broadcast_info info;

    rc = initialize(argc, argv, &info);
    if(rc != 0){ 
        fprintf(stderr, "Error: failed to initialize.\n");
        return -1;
    }   

    rc = broadcast_receiver(&info);
    if(rc != 0){ 
        fprintf(stderr, "Error: failed to broadcast_receive.\n");
        return -1;
    }

    return 0;
}