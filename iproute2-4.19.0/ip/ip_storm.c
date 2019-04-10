/*
 * ip_storm.c 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/un.h>
#include <linux/genetlink.h>
#include <storm.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"
#include "libnetlink.h"

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004
#define PPS				0x0001
#define BPS				0x0002
#define LEVEL				0x0004
#define FLAG_UP				0x0001
#define FLAG_DOWN			0x0002

static struct rtnl_handle genl_rth;
static int genl_family = -1;

static void usage(void)__attribute__((noreturn));

void usage(void)
{
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

static int parse_args(int argc,char **argv,struct storm_info *s_info)
{
	/* ip storm dev ens33 type broadcast pps 14000*/

	memset(s_info,0,sizeof(struct storm_info));
	
	if(argc < 1){
		usage();
	}
	
	while(argc > 0){
		if(strcmp(*argv,"dev") == 0){
			argc--;
			argv++;
			strncpy(s_info->if_name,*argv,STORM_DEVNAME_MAX);
		}
		else if(strcmp(*argv,"type") == 0){
			argc--;
			argv++;
			if(strcmp(*argv,"multicast") == 0){
				s_info->traffic_type = TRAFFIC_TYPE_MULTICAST;
				s_info->first_flag = FLAG_UP;
				s_info->drop_flag = FLAG_DOWN;
			}
			else if(strcmp(*argv,"broadcast") == 0){
				s_info->traffic_type = TRAFFIC_TYPE_BROADCAST;
				s_info->first_flag = FLAG_UP;
				s_info->drop_flag = FLAG_DOWN;
			}		
			else if(strcmp(*argv,"unknown_unicast") == 0){
				s_info->traffic_type = TRAFFIC_TYPE_UNKNOWN_UNICAST;
				s_info->first_flag = FLAG_UP;
				s_info->drop_flag = FLAG_DOWN;
			}
		}
		else if(strcmp(*argv,"pps") == 0){
			s_info->pb_type = PPS;
			argc--;
			argv++;
			s_info->threshold = atoi(*argv);
			argc--;
			argv++;
			if(argc > 0){
				argc--;
				argv++;
				s_info->low_threshold = atoi(*argv);
			}
		}
		else if(strcmp(*argv,"bps") == 0){
			s_info->pb_type = BPS;
			argc--;
			argv++;
			s_info->threshold = atoi(*argv);
			argc--;
			argv++;
			if(argc > 0){
				argc--;
				argv++;
				s_info->low_threshold = atoi(*argv);
			}		
		}
		else{
			fprintf(stderr,
				"Error: Invalid argument \"%s\"\n", *argv);
			usage();
		}
		argc--;
		argv++;
	}

	return 0;
} 

static int do_add(int argc, char **argv)
{
	struct storm_info s_info;

	if(parse_args(argc,argv,&s_info)<0){
		return -1;
	}

	GENL_REQUEST(req,1024, genl_family, 0, STORM_GENL_VERSION,
		     STORM_CMD_ADD_IF, NLM_F_REQUEST | NLM_F_ACK);
	
	addattr_l(&req.n,1024,STORM_ATTR_IF,&s_info,sizeof(s_info));

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0){
			return -2;
	}

	return 0;


}

static int do_del(int argc, char **argv)
{
	struct storm_info s_info;

	if(parse_args(argc,argv,&s_info)<0){
		return -1;
	}

	GENL_REQUEST(req,1024, genl_family, 0, STORM_GENL_VERSION,
		     STORM_CMD_DEL_IF,NLM_F_REQUEST | NLM_F_ACK);

	addattr_l(&req.n,1024,STORM_ATTR_IF,&s_info,sizeof(s_info));

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0){
			return -2;
	}

	return 0;

}

int do_ipstorm(int argc, char **argv){

	if (argc < 1 || !matches(*argv, "help")){
		usage();
	}

	if (genl_init_handle(&genl_rth,STORM_GENL_NAME,&genl_family)){
		exit(-1);
	}
	
	if(matches(*argv,"add") == 0){
		return do_add(argc - 1, argv + 1);
	}
	if(matches(*argv,"del") == 0 ||
		matches(*argv,"delete") == 0){
			return do_del(argc - 1 , argv + 1);
	}

	fprintf(stderr,
		"Command \"%s\" is unkonw, type \"ip storm help\".\n", *argv);

	exit(-1);
}
