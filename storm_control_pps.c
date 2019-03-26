/* 
 * Traffic storm control module for linux kernel
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <linux/net_namespace.h>
#include<linux/mutex.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/ip.h>
#include <net/route.h>


MODULE_LICENSE("Debian");
MODULE_AUTHOR("siibaa");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");

/* the interface name a user can specify*/
static char *d_name;
module_param(d_name,charp,0660);


/* the traffic type a user want to control storm*/
static char *traffic_type;
module_param(traffic_type,charp,0660);

/* the threthhold that set the traffic limit*/
static int threshold = 0;
module_param(threshold,int,0664);

/* the the threthold for low level limit*/
static int low_threshold = 0;
module_param(low_threshold,int,0664);

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004
#define FLAG_UP				0x0001
#define FLAG_DOWN			0x0002
#define TIMER_TIMEOUT_SECS    	1


struct storm_control_dev{
	struct net_device *dev;
	int p_counter;
    	u16 d_flag; /*drop_flag*/
	u16 f_flag; /*first time or not*/
	u16 t_type; /* user specified traffic type*/
};
static struct storm_control_dev sc_dev;

/*per cpu packet*/
static DEFINE_PER_CPU(int,pc_packet);

struct timer_list sc_timer;

static DEFINE_MUTEX(cpu_mutex);

/* a prototype for ip_route_input */
int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin);


static int total_cpu_packet(int pcp)
{
	int cpu;
	int total_packet = 0;

	/*read_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		total_packet += per_cpu(pcp,cpu);
	}
	mutex_unlock(&cpu_mutex);
	/*read_unlock();*/

	return total_packet;
}

static void initialize_cpu_counter(int pcp)
{
	int cpu;
		/*write_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		per_cpu(pcp,cpu) = 0;
	}
	mutex_unlock(&cpu_mutex);
		/*write_unlock();*/
}

static void threshold_comparison(void){
	if(sc_dev.p_counter >= threshold && (sc_dev.d_flag & FLAG_DOWN)){
		sc_dev.d_flag = FLAG_UP;
		sc_dev.p_counter = 0;
		initilaize_cpu_counter(pc_packet);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet per second was more than the threthold.\n");
	    	printk(KERN_INFO "--------Blocking started--------\n");
	    	printk(KERN_INFO "Packet was dropped .\n");
    }
    else if(sc_dev.p_counter < threshold && (sc_dev.d_flag & FLAG_DOWN)){
		sc_dev.p_counter = 0;
		initialize_cpu_counter(pc_packet);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet pakcet per second was less than the threthold.\n");
	    	printk(KERN_INFO "Packet was accepted .\n");
    }
    else if(sc_dev.p_counter >= low_threshold && (sc_dev.d_flag & FLAG_UP)){
		sc_dev.p_counter = 0;
	    	initialize_cpu_counter(pc_packet);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet pakcet per second was more than the lowthrethold.\n");
	    	printk(KERN_INFO "Dropping packet continues.\n");
    }
    else if(sc_dev.p_counter < low_threshold && (sc_dev.d_flag & FLAG_UP)){
	    	sc_dev.d_flag = FLAG_DOWN;
		sc_dev.p_counter = 0;
		initialize_cpu_counter(pc_packet);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet per second was less than the threthold.\n");
	    	printk(KERN_INFO "--------Packet blocking ended.--------\n");
    }
}

static void check_packet(unsigned long data)
{
	printk(KERN_INFO "--------One Second passed--------\n");
	sc_dev.p_counter = total_cpu_packet(pc_packet);
    	packet_check();
}

static int route4_input(struct sk_buff *skb)
{
	struct iphdr *hdr;
	int err;

	if (!skb->dev) {
		printk(KERN_INFO "skb lacks an incoming device.");
		return -EINVAL;
	}

	hdr = ip_hdr(skb);
	err = ip_route_input(skb, hdr->daddr, hdr->saddr, hdr->tos, skb->dev);
	if(err){

		return -1;
	}

	return 0;
}

/*
タイマーが同時にセットされたらまずいので、最初のタイマーセットは必ず一回のみ
そうすれば、そのタイマーが発火した時にcheckが呼び出されて、カウンターをチェックして、
二度目以降のタイマーセットも最初のタイマーを持っている関数にしか実行できなくなる

timer,hook,dev_put,その他関数、メモリ
*/

/*the function hooks incoming packet*/
static unsigned int
storm_hook(
	void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{       
	if(!skb){
            return NF_ACCEPT;
        }

        if(skb->dev == sc_dev.dev){
	    /*Broadcast processing*/
	    	if(skb->pkt_type == PACKET_BROADCAST && (sc_dev.t_type & TRAFFIC_TYPE_BROADCAST)){
	    		if((sc_dev.f_flag & FLAG_UP) && (sc_dev.d_flag & FLAG_DOWN)){
					sc_dev.f_flag = FLAG_DOWN;
					printk(KERN_INFO "First broadcast packet was arrived.\n");
					printk(KERN_INFO "One second timer started.\n");
					add_timer(&sc_timer);
					this_cpu_inc(pc_packet);
					return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag & FLAG_DOWN){
				this_cpu_inc(pc_packet);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag & FLAG_UP){
				this_cpu_inc(pc_packet);
				return NF_DROP;
			}
		}
	    	else if(skb->pkt_type == PACKET_MULTICAST && (sc_dev.t_type & TRAFFIC_TYPE_MULTICAST)){
	    		if((sc_dev.f_flag & FLAG_UP) && (sc_dev.d_flag & FLAG_DOWN)){
					sc_dev.f_flag = FLAG_DOWN;
					printk(KERN_INFO "First multicast packet was arrived.\n");
					printk(KERN_INFO "--------One second timer started--------\n");
					add_timer(&sc_timer);
					this_cpu_inc(pc_packet);
				return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag & FLAG_DOWN){
				this_cpu_inc(pc_packet);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag & FLAG_UP){
				this_cpu_inc(pc_packet);
				return NF_DROP;
			}
		}
		else if((route4_input(skb) == -1) && (sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)){
			if((sc_dev.f_flag & FLAG_UP) && (sc_dev.d_flag & FLAG_DOWN)){
				sc_dev.f_flag = FLAG_DOWN;
				printk(KERN_INFO "First unknown unicast packet was arrived.\n");
				printk(KERN_INFO "--------One second timer started--------\n");
				add_timer(&sc_timer);
				this_cpu_inc(pc_packet);
				return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag & FLAG_DOWN){
				this_cpu_inc(pc_packet);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag & FLAG_UP){
				this_cpu_inc(pc_packet);
				return NF_DROP;
			}
		}
		else{
			return NF_ACCEPT;
		}
	}
	else{
		return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops_storm __read_mostly = {
	.hook = storm_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};
    
static int 
__init stctl_init_module(void)
{       
        int ret = 0;

	memset(&sc_dev,0,sizeof(sc_dev));
    	initialize_cpu_counter(pc_packet);

	init_timer(&sc_timer);
	sc_timer.expires = jiffies + TIMER_TIMEOUT_SECS*HZ;
	sc_timer.data = 0;
	sc_timer.function = check_packet;
	
	sc_dev.dev = dev_get_by_name(&init_net,d_name);
	if (!sc_dev.dev){
		return -ENODEV;
	}

    	ret = nf_register_hook(&nf_ops_storm);

        if(ret){
                printk(KERN_DEBUG "failed to register hook.\n");
        }

	if(strcmp(traffic_type,"broadcast") == 0){
		sc_dev.t_type = TRAFFIC_TYPE_BROADCAST;
		sc_dev.f_flag = FLAG_UP;
		sc_dev.d_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is broadcast.\n");
        }
        else if(strcmp(traffic_type,"multicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_MULTICAST;
		sc_dev.f_flag = FLAG_UP;
		sc_dev.d_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is multicast.\n");
        }
	else if(strcmp(traffic_type,"unknown_unicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_UNKNOWN_UNICAST;
		sc_dev.f_flag = FLAG_UP;
		sc_dev.d_flag = FLAG_DOWN;
		printk(KERN_INFO "Control target is unknown_unicast.\n");
	}
        else{
            printk(KERN_DEBUG "this traffic type could not be registered.\n");
        }

	printk (KERN_INFO "storm_control module is loaded\n");

        return 0;
}
module_init(stctl_init_module);


static void 
__exit stctl_exit_module(void)
{
	dev_put(sc_dev.dev);
	nf_unregister_hook(&nf_ops_storm);
	del_timer(&sc_timer);
    	printk(KERN_INFO "Storm control module was Removed.\n");
}
module_exit(stctl_exit_module);