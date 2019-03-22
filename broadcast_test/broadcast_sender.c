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
typedef struct broadcast_info bc_info_t;

static int
socket_initialize(bc_info_t *info, char *errmsg)
{
    int rc = 0;

    info->sd = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(info->sd < 0){
        sprintf(errmsg, "(line:%d) %s", __LINE__, strerror(errno));
        return(-1);
    }

    rc = setsockopt(info->sd, SOL_SOCKET, SO_BROADCAST,
                    (void *)&(info->permission), sizeof(info->permission));
    if(rc != 0){
        sprintf(errmsg, "(line:%d) %s", __LINE__, strerror(errno));
        return -1;
    }

    info->addr.sin_family = AF_INET;
    info->addr.sin_addr.s_addr = inet_addr(info->ipaddr);
    info->addr.sin_port = htons(info->port);

    return 0;
}


static void
socket_finalize(bc_info_t *info)
{
    /* ソケット破棄 */
    if(info->sd != 0) close(info->sd);

    return;
}

static int
broadcast_sendmsg(bc_info_t *info, char *errmsg)
{
    int sendmsg_len = 0;

    /* ブロードキャストを送信し続ける */
    while(1){
        sendmsg_len = sendto(info->sd, info->msg, info->msg_len, 0,
                             (struct sockaddr *)&(info->addr),
                              sizeof(info->addr));
        if(sendmsg_len != info->msg_len){
            sprintf(errmsg, "invalid msg is sent.(%s)",
                     __LINE__, strerror(errno));
            return(-1);
        }
        sleep(5);
    }

    return(0);
}

static int
broadcast_sender(bc_info_t *info, char *errmsg)
{
    int rc = 0;

    /* ソケットの初期化 */
    rc = socket_initialize(info, errmsg);
    if(rc != 0) return(-1);

    /* ブロードキャストを送信する */
    rc = broadcast_sendmsg(info, errmsg);

    /* ソケットの終期化 */
    socket_finalize(info);

    return(0);
}


static int
initialize(int argc, char *argv[], bc_info_t *info, char *errmsg)
{
    if(argc != 4){
        sprintf(errmsg, "Usage: %s <ip-addr> <port> <msg>", argv[0]);
        return(-1);
    }

    memset(info, 0, sizeof(bc_info_t));
    info->ipaddr     = argv[1];
    info->port       = atoi(argv[2]);
    info->msg        = argv[3];
    info->msg_len    = strlen(argv[3]);
    info->permission = 1;

    return(0);
}
int
main(int argc, char *argv[])
{
    int rc = 0;
    bc_info_t info = {0};
    char errmsg[BUFSIZ];

    rc = initialize(argc, argv, &info, errmsg);
    if(rc != 0){
        fprintf(stderr, "Error: %s\n", errmsg);
        return(-1);
    }

    rc = broadcast_sender(&info, errmsg);
    if(rc != 0){
        fprintf(stderr, "Error: %s\n", errmsg);
        return(-1);
    }

    return(0);
}