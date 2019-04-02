#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

struct broadcast_info {
    unsigned short port;     
    char *ipaddr;            
    char *msg;               
    unsigned int msg_len;    
    int sd;                  
    struct sockaddr_in addr; 
    int permission;          
};

static int
socket_initialize(struct broadcast_info *info)
{
    int rc = 0;

    info->sd = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(info->sd < 0){
        perror("socket");
        return -1;
    }

    rc = setsockopt(info->sd, SOL_SOCKET, SO_BROADCAST,
                    (void *)&(info->permission), sizeof(info->permission));
    if(rc != 0){
        perror("setsocketopt");
        return -1;
    }

    info->addr.sin_family = AF_INET;
    info->addr.sin_addr.s_addr = inet_addr(info->ipaddr);
    info->addr.sin_port = htons(info->port);

    return 0;
}


static void
socket_finalize(struct broadcast_info *info)
{
    if(info->sd != 0){
        close(info->sd);
    }

}

static int
broadcast_sendmsg(struct broadcast_info *info)
{
    int sendmsg_len = 0;

    while(1){
        sendmsg_len = sendto(info->sd, info->msg, info->msg_len, 0,
                             (struct sockaddr *)&(info->addr),
                              sizeof(info->addr));
        if(sendmsg_len != info->msg_len){
            fprintf(stderr,"rudp_sendto:sendto failed\n");
            return -1;
        }
    }

    return 0;
}

static int
broadcast_sender(struct broadcast_info *info)
{
    int rc = 0;

    rc = socket_initialize(info);
    if(rc != 0){
        return -1;
    }

    rc = broadcast_sendmsg(info);

    socket_finalize(info);

    return 0;
}


static int
initialize(int argc, char *argv[], struct broadcast_info *info)
{
    if(argc != 4){
        printf("Usage: <ip-addr> <port> <msg>\n");
        return(-1);
    }

    memset(info, 0, sizeof(struct broadcast_info));
    info->ipaddr     = argv[1];
    info->port       = atoi(argv[2]);
    info->msg        = argv[3];
    info->msg_len    = strlen(argv[3]);
    info->permission = 1;

    return 0;
}
int
main(int argc, char *argv[])
{
    int rc = 0;
    struct broadcast_info info;

    rc = initialize(argc, argv, &info);
    if(rc != 0){
        fprintf(stderr, "Error: failed to initialize. \n");
        return -1;
    }

    rc = broadcast_sender(&info);
    if(rc != 0){
        fprintf(stderr, "Error: failed to broadcast_send.\n");
        return -1;
    }

    return 0;
}
