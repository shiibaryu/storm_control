/* 
 * Traffic storm control module for linux kernel
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
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
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/route.h>
#include <linux/ip.h>

MODULE_LICENSE("Debian");
MODULE_AUTHOR("siibaa");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");

/* the interface name a user can specify*/
static char *d_name;
module_param(d_name,charp,0660);

/* the traffic type a user want to control storm*/
static char *traffic_type;
module_param(traffic_type,charp,0660);

/* bps or pps*/
/*static char *per_second;
module_param(per_second,charp,0660);*/

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


struct packet_counter{
	int b_counter; /* the counter for broadcast*/
	int m_counter; /* the counter for multicast*/
	int uu_counter; /* the counter for unknown unicast*/
};

struct drop_flag{
	u16 b_flag; /*the time at when first broadcast packet arrived*/
	u16 m_flag; /*the time at when first multidcast packet arrived*/
	u16 uu_flag; /*the time at when first unknown_unicast packet arrived*/
};

struct first_packet_flag{
	u16 b_flag:
	u16 m_flag;
	u16 uu_flag;
};

struct storm_control_dev{
	struct net_device *dev;
	struct packet_counter *p_counter;
	struct drop_flag *d_flag;
	struct first_packet_flag *f_flag;
	int threshold; /* threshold to start blocking bum packet*/
	int low_threshold; /* threshold to stop blocking specified packet*/
	u16 t_type; /* user specified traffic type*/
};
static struct storm_control_dev sc_dev;

struct per_cpu_counter{
	int pc_b_counter; /* per cpu bloadcast packet counter */
	int pc_m_counter; /* per cpu multicast packet counter */
	int pc_uu_counter; /* per cpu unknown unicast packet counter */
};

/*各パケット対応timerとcpu_counter*/

static DEFINE_PER_CPU(struct per_cpu_counter,pcc);

int g_time_interval = 1000;
struct timer_list g_timer;

static DEFINE_MUTEX(cpu_mutex);

/* a prototype for ip_route_input */
int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin);


static int total_cpu_packet(struct per_cpu_counter pc)
{
	int cpu;
	int total_packet;

	if(sc_dev.t_type & TRAFFIC_TYPE_BROADCAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_b_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_unlock()*/
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_MULTICAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_m_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_unlock()*/
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_uu_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_unlock()*/
	}

	return total_packet;
}

static void initilize_cpu_counter(struct per_cpu_counter pc)
{
	int cpu;

	if(sc_dev.t_type & TRAFFIC_TYPE_BROADCAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_b_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_lock()*/
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_MULTICAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_m_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_lock()*/

	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		/*rcu_read_lock()*/
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_uu_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
		/*rcu_read_lock()*/
	}
}

static void broadcast_packet_check(void){
	if(sc_dev.p_counter->b_counter >= threshold && (sc_dev.d_flag->b_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer( &g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->b_counter = 0;
	    sc_dev.d_flag->b_flag = FLAG_UP;
	    printk(KERN_INFO "Broadcast pakcet per second was more than the threthold.\n");
	    printk(KERN_INFO "--------Broadcast blocking started--------\n");
	    printk(KERN_INFO "Broadcast packet was dropped .\n");
    }
    else if(sc_dev.p_counter->b_counter < threshold && (sc_dev.d_flag->b_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->b_counter = 0;
	    printk(KERN_INFO "Broadcast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "Broadcast packet was accepted .\n");
    }
    else if(sc_dev.p_counter->b_counter >= low_threshold && (sc_dev.d_flag->b_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->b_counter = 0;
	    printk(KERN_INFO "Broadcast pakcet per second was more than the lowthrethold.\n");
	    printk(KERN_INFO "Dropping Broadcast packet continues.\n");
    }
    else if(sc_dev.p_counter->b_counter < low_threshold && (sc_dev.d_flag->b_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->b_counter = 0;
	    sc_dev.d_flag->b_flag = FLAG_DOWN;
	    printk(KERN_INFO "Broadcast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "--------Broadcast blocking ended.--------\n");
    }
}

static void multicast_packet_check(void){
	if(sc_dev.p_counter->m_counter >= threshold && (sc_dev.d_flag->m_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->m_counter = 0;
	    sc_dev.d_flag->m_flag = FLAG_UP;
	    printk(KERN_INFO "Multicast pakcet per second was more than the threthold.\n");
	    printk(KERN_INFO "--------Multicast blocking started--------\n");
	    printk(KERN_INFO "Multicast packet was dropped .\n");
    }
    else if(sc_dev.p_counter->m_counter < threshold && (sc_dev.d_flag->m_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->m_counter = 0;
	    printk(KERN_INFO "Multicast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "Multicast packet was accepted .\n");
    }
    else if(sc_dev.p_counter->m_counter >= low_threshold && (sc_dev.d_flag->m_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->m_counter = 0;
	    printk(KERN_INFO "Multicast pakcet per second was more than the low threthold.\n");
	    printk(KERN_INFO "Dropping Multicast packet continues.\n");
    }
    else if(sc_dev.p_counter->m_counter < low_threshold && (sc_dev.d_flag->m_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->m_counter = 0;
	    sc_dev.d_flag->m_flag = FLAG_DOWN;
	    printk(KERN_INFO "Multicast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "--------Multicast blocking ended--------.\n");
    }
}

static void unknown_unicast_packet_check(void){
	if(sc_dev.p_counter->uu_counter >= threshold && (sc_dev.d_flag->uu_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->uu_counter = 0;
	    sc_dev.d_flag->uu_flag = FLAG_UP;
	    printk(KERN_INFO "Unknown Unicast pakcet per second was more than the threthold.\n");
	    printk(KERN_INFO "--------Unknown Unicast blocking started--------\n");
	    printk(KERN_INFO "Unknown Unicast packet was dropped .\n");
    }
    else if(sc_dev.p_counter->uu_counter < threshold && (sc_dev.d_flag->uu_flag & FLAG_DOWN)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->uu_counter = 0;
	    printk(KERN_INFO "Unknown Unicast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "Unknown Unicast packet was accepted .\n");
    }
    else if(sc_dev.p_counter->uu_counter >= low_threshold && (sc_dev.d_flag->uu_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->uu_counter = 0;
	    printk(KERN_INFO "Unknown Unicast pakcet per second was more than the low threthold.\n");
	    printk(KERN_INFO "Dropping Unknown Unicast packet continues.\n");
    }
    else if(sc_dev.p_counter->uu_counter < low_threshold && (sc_dev.d_flag->uu_flag & FLAG_UP)){
	    initilize_cpu_counter(pcc);
	    mod_timer(&g_timer, jiffies + msecs_to_jiffies(g_time_interval));
	    sc_dev.p_counter->uu_counter = 0;
	    sc_dev.d_flag->uu_flag = FLAG_DOWN;
	    printk(KERN_INFO "Unknown Unicast pakcet per second was less than the threthold.\n");
	    printk(KERN_INFO "--------Unknown Unicast blocking ended--------.\n");
    }
}

static void check_packet(unsigned long data)
{
	printk(KERN_INFO "--------One Second passed--------\n");
	sc_dev.p_counter->b_counter = total_cpu_packet(pcc);

	if(sc_dev.t_type & TRAFFIC_TYPE_BROADCAST){
		broadcast_packet_check();
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_MULTICAST){
		multicast_packet_check();
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		unknown_unicast_packet_check();
	}
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
	    		if((sc_dev.f_flag->b_flag & FLAG_UP) && (sc_dev.d_flag->b_flag & FLAG_DOWN)){
				sc_dev.f_flag->b_flag = FLAG_DOWN;
				printk(KERN_INFO "First broadcast packet was arrived.\n");
				printk(KERN_INFO "One second timer started.\n");
				setup_timer(&g_timer,check_packet, 0);
				mod_timer( &g_timer, jiffies + msecs_to_jiffies(g_time_interval));
				this_cpu_inc(pcc.pc_b_counter);
				return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag->b_flag & FLAG_DOWN){
				this_cpu_inc(pcc.pc_b_counter);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag->b_flag & FLAG_UP){
				this_cpu_inc(pcc.pc_b_counter);
				return NF_DROP;
			}
		}
	    	else if(skb->pkt_type == PACKET_MULTICAST && (sc_dev.t_type & TRAFFIC_TYPE_MULTICAST)){
	    		if((sc_dev.f_flag->m_flag & FLAG_UP) && (sc_dev.d_flag->m_flag & FLAG_DOWN)){
				sc_dev.f_flag->m_flag = FLAG_DOWN;
				printk(KERN_INFO "First multicast packet was arrived.\n");
				printk(KERN_INFO "--------One second timer started--------\n");
				setup_timer(&g_timer,check_packet, 0);
				mod_timer( &g_timer, jiffies + msecs_to_jiffies(g_time_interval));
				this_cpu_inc(pcc.pc_m_counter);
				return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag->m_flag & FLAG_DOWN){
				this_cpu_inc(pcc.pc_m_counter);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag->m_flag & FLAG_UP){
				this_cpu_inc(pcc.pc_m_counter);
				return NF_DROP;
			}
		}
		else if((route4_input(skb) == -1) && (sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)){
			if((sc_dev.f_flag->uu_flag & FLAG_UP) && (sc_dev.d_flag->uu_flag & FLAG_DOWN)){
				sc_dev.f_flag->uu_flag = FLAG_DOWN;
				printk(KERN_INFO "First unknown unicast packet was arrived.\n");
				printk(KERN_INFO "--------One second timer started--------\n");
				setup_timer(&g_timer,check_packet, 0);
				mod_timer( &g_timer, jiffies + msecs_to_jiffies(g_time_interval));
				this_cpu_inc(pcc.pc_uu_counter);
				return NF_ACCEPT;
	    		}
			else if(sc_dev.d_flag->uu_flag & FLAG_DOWN){
				this_cpu_inc(pcc.pc_uu_counter);
				return NF_ACCEPT;
			}
			else if(sc_dev.d_flag->uu_flag & FLAG_UP){
				this_cpu_inc(pcc.pc_uu_counter);
				return NF_DROP;
			}
		}
		else{
			return NF_ACCEPT;
		}
	else{
		return NF_ACCEPT;
	}
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
	memset(&pcc,0,sizeof(pcc));
	
	sc_dev.dev = dev_get_by_name(&init_net,d_name);

        ret = nf_register_hook(&nf_ops_storm);

        if(ret){
                printk(KERN_DEBUG "failed to register hook.\n");
        }
	printk (KERN_INFO "storm_control module is loaded\n");

	if(strcmp(traffic_type,"broadcast") == 0){
		sc_dev.t_type = TRAFFIC_TYPE_BROADCAST;
		sc_dev.f_flag->b_flag = FLAG_UP;
		sc_dev.d_flag->b_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is broadcast.\n");
        }
        else if(strcmp(traffic_type,"multicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_MULTICAST;
		sc_dev.f_flag->m_flag = FLAG_UP;
		sc_dev.d_flag->m_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is multicast.\n");
        }
	else if(strcmp(traffic_type,"unknown_unicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_UNKNOWN_UNICAST;
		sc_dev.f_flag->uu_flag = FLAG_UP;
		sc_dev.d_flag->uu_flag = FLAG_DOWN;
		printk(KERN_INFO "Control target is unknown_unicast.\n");
	}
        else{
            printk(KERN_DEBUG "this traffic type could not be registered.\n");
        }

        return 0;
}
module_init(stctl_init_module);


static void 
__exit stctl_exit_module(void)
{
	/*free_percpu(&pcc);*/
	nf_unregister_hook(&nf_ops_storm);
	del_timer(&g_timer);
    	printk(KERN_INFO "Storm control module was Removed.\n");
}
module_exit(stctl_exit_module);
