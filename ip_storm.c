/*
 * storm_ctl.c 
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

#include 

#define CMD_SIZE 6
#define device_name_max 10
#define traffic_name_max 15
#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004

struct storm_param{
	char dev[device_name_max];
	char traffic_type[traffic_name_max];
	u16  control_type;
	int  threshold;
	int  low_threshold;
};

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
			strncpy(sp->dev,argv,sizeof(argv);
		}
		else if(strcmp(*argv,"type") == 0){
			argc--;
			argv++;
			strncpy(sp->traffic_type,argv,sizeof(argv);			
		}
		else if(strcmp(*argv,"pps") == 0){
			argc--;
			argv++;
			strncpy(sp->control_type,argv,sizeof(argv);			
		}
		else if(strcmp(*argv,"bps") == 0){
			argc--;
			argv++;
			strncpy(sp->control_type,argv,sizeof(argv);			
		}
		else if(strcmp(*argv,"level") == 0){
			argc--;
			argv++;
			strncpy(sp->control_type,argv,sizeof(argv);			
		}
		else if(*argv == ){
			argc--;
			argv++;
			sp->threshold = (int *)argv;
		}
		else if(strcmp(*argv,"数字") == 0){
			argc--;
			argv++;
			sp->low_threshold = (int *)argv;
		}
		else{
			fprintf(stderr,
				"Error: Invalid argument \"%s\"\n", *argv);
			usage();
		}
	}

	return 0;
} 

/*構造体を登録して、アドレスをparseの関数に渡し、
　パースしてもらって、構造体がつまり、その詰まった構造体
　をカーネルへ送る関数を定義し、送る関数を作る(あとは多分削除用とかshow用がいるけど、ひとまず削除だけでいいかな)
　それができたら、メイン関数にparseとそのさっきの関数を登録して、カーネルにメッセージが送られる
　 カーネルにメッセージが送られたら、それを元にdoitの関数が動き、そこでdevとppsをセットして、flagをonにすれば
　 動くって感じ？*/


static int send_msg_kernel(struct nl_sock *sock)
{


}

int main(int argc, char *argv){
	struct storm_param ps;

	/*構造体にデータを詰め込む*/
	parse_args(argc,argv,&ps);
	
	/*メモリの準備*/
	prep_nl_sock(&nlsock);
	/*ソケット繋いで、構造体を送る*/
	send_msg_kernel(ps,);

	/*そうなると、カーネル側でdoit関数が動き、送ったメッセージを受け取り、あっちで
	  グローバルに宣言している構造体の変数に入れ込んだり、フラグをいじればいける！！！
	*/

	return 0;
}
