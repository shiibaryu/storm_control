/*
 * ip_storm.c 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/un.h>
#include <linux/genetlink.h>

#include "utils.h"
#include "ip_common.h"


#define CMD_SIZE 						6
#define device_name_max 				10
#define traffic_name_max 				15
#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004

struct storm_param{
	char dev[device_name_max];
	u16  traffic_type[traffic_name_max];
	char control_type[6];
	int  threshold;
	int  low_threshold;
}__attribute__((__packed__));

void usage(void){
	fprintf(stderr,
		"Usage: ip storm add dev NAME\n"
		"          type { broadcast | multicast | unknown_unicast }\n"
		"          { pps | bps | level } threshold low_threshold\n"
		"\n"
		"       ip storm del dev NAME\n"
		"\n"
		"       ip storm show\n"
		"\n"
		);

	exit(-1);

}

static int parse_args(int argc,char **argv,struct storm_param *sp)
{
	/* ip storm dev ens33 type broadcast pps 14000*/

	if(argc < 1){
		usage();
	}

	if (strlen(*argv) > STORM_EPNAME_MAX) {
		fprintf(stderr,
			"Error: "
			"endpoint name must be less than %d characters\n",
			STORM_EPNAME_MAX);
		exit(-1);
	}
	strncpy(name, *argv, STORM_EPNAME_MAX - 1);

	argc--;
	argv++:

	while(argc > 0){
		if(strcmp(*argv,"ip") == 0){
			argc--;
			argv++;
			/*NEXT_ARG();*/
		}
		else if(strcmp(*argv,"storm") == 0){
			argc--;
			argv++;
			/*NEXT_ARG();*/
		}
		else if(strcmp(*argv,"dev") == 0){
			argc--;
			argv++;
			strncpy(sp->dev,argv,sizeof(argv));
		}
		else if(strcmp(*argv,"type") == 0){
			argc--;
			argv++;
			if(strcmp(*argv,"multicast") == 0){
				strncpy(sp->traffic_type,TRAFFIC_TYPE_MULTICAST,sizeof(u16)));	
			}
			else if(strcmp(*argv,"broadcast") == 0){
				strncpy(sp->traffic_type,TRAFFIC_TYPE_BROADCAST,sizeof(u16));	
			}		
			else if(strcmp(*argv,"unknown_unicast") == 0){
				strncpy(sp->traffic_type,TRAFFIC_TYPE_UNKNOWN_UNICAST,sizeof(u16));	
			}
		}
		else if(strcmp(*argv,"pps") == 0){
			strncpy(sp->control_type,argv,sizeof(argv));		
			argc--;
			argv++;
			sp->threshold = atoi(*argv);
			argc--;
			argv++;
			if(atoi(*argv) != NULL){
				sp->low_threshold = atoi(*argv);
			}
		}
		else if(strcmp(*argv,"bps") == 0){
			strncpy(sp->control_type,argv,sizeof(argv));		
			argc--;
			argv++;
			sp->threshold = atoi(*argv);
			argc--;
			argv++;
			if(atoi(*argv) != NULL){
				sp->low_threshold = atoi(*argv);
			}		
		}
		else if(strcmp(*argv,"level") == 0){
			argc--;
			argv++;
			sp->threshold = atoi(*argv);
			argc--;
			argv++;
			if(atoi(*argv) != NULL){
				sp->low_threshold = atoi(*argv);
			}	
		}
		else{
			fprintf(stderr,
				"Error: Invalid argument \"%s\"\n", *argv);
			usage();
		}
	}

	return 0;
} 

static int send_msg_kernel(int argc,char **argv)
{
	struct storm_param ps;

	if(parse_args(argc,argv,&ps) < 0){
		return -1;
	}

	GENL_REQUEST(req,1024, genl_family, 0, STORM_GENL_VERSION,
		     STORM_CMD_ADD_ENDPOINT, NLM_F_REQUEST | NLM_F_ACK);
	
	addattr_l(&req.n,1024,STORM_ATTR_ENDPOINT,&ps,sizeof(ps));

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0){
			return -2;
	}

	return 0;
}

int main(int argc, char *argv){

	int rec;

	if (argc < 1 || !matches(*argv, "help")){
		usage();
	}

	if (genl_init_handle(&genl_rth, STORM_GENL_NAME, &genl_family)){
		exit(-1);
	}
	
	ret = send_msg_kernel(argc,argv);
	if(ret < 0){
		printf("failed to send msg to kernel.");
		return -1;
	}

	return 0;
}

/*struct nl_sock *sock;
	struct nl_msg *msg;
	int family;*/

/*allocate a new netlink socket*/
	/*sock = nl_socket_alloc();
	if(!sock) {
		fprintf(stderr, "Unable to alloc nl socket!\n");
		exit(EXIT_FAILURE);
	}*/

	/*Connect to generic netlink socket on kernel side*/
	/*if (genl_connect(sock)) {
		fprintf(stderr, "Unable to connect to genl!\n");
		goto exit_err;
	}

	family = genl_ctrl_resolve(sock,);

	msg = nlmsg_alloc();
	if(!genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family_id, 0, NLM_F_REQUEST, GENL_TEST_C_MSG, 0)) {
		fprintf(stderr, "failed to put nl hdr!\n");
		err = -ENOMEM;
		goto out;

			out:
	nlmsg_free(msg);
	return err;
	}*/
	