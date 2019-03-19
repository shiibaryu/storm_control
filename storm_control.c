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
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/if_packet.h>
#include <linux/types.h>
#include <linux/net_namespace.h>
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

struct packet_counter{
	int b_counter; /* the counter for broadcast*/
	int m_counter; /* the counter for multicast*/
	int uu_counter; /* the counter for unknown unicast*/
};

struct block_flag{
	int b_flag; /*the flag that represents whether broadcast blocking is on or not*/
	int m_flag; /*the flag that represents whether multicast blocking is on or not*/
	int uu_flag; /*the flag that represents whether unknonw unicast blocking is on or not*/
};

struct packet_time{
	ktime_t first_b_time; /*the time at when first broadcast packet arrived*/
	ktime_t first_m_time; /*the time at when first multidcast packet arrived*/
	ktime_t first_uu_time; /*the time at when first unknown_unicast packet arrived*/
	ktime_t block_b_time; /*the time when broadcast packet blocking started*/
	ktime_t block_m_time; /*the time when multicast packet blocking started*/
	ktime_t block_uu_time; /*the time at when unknown unicast packet blocking started*/
};

struct storm_control_dev{
	struct net_dev *dev;
	struct packet_counter *p_counter;
	struct block_flag *b_flag;
	struct packet_time *p_time;
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


static DEFINE_PER_CPU(struct per_cpu_counter,pcc);

static DEFINE_MUTEX(cpu_mutex);

/* a prototype for ip_route_input */
int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin);


static int total_cpu_packet(struct per_cpu_counter pc)
{
	int cpu;
	int total_packet;

	if(sc_dev.t_type & TRAFFIC_TYPE_BROADCAST){
		this_cpu_inc(pc.pc_b_counter);
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_b_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_MULTICAST){
		this_cpu_inc(pc.pc_m_counter);
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_m_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
	}
	else if(sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		this_cpu_inc(pc.pc_uu_counter);
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			total_packet += per_cpu(pc.pc_uu_counter,cpu);
		}
		mutex_unlock(&cpu_mutex);
	}


	return total_packet;
}

static void initilize_cpu_counter(struct per_cpu_counter pc)
{
	int cpu;

	if((sc_dev.t_type & TRAFFIC_TYPE_BROADCAST) == TRAFFIC_TYPE_BROADCAST){
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_b_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
	}
	else if((sc_dev.t_type & TRAFFIC_TYPE_MULTICAST)== TRAFFIC_TYPE_MULTICAST){
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_m_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
	}
	else if((sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)== TRAFFIC_TYPE_UNKNOWN_UNICAST){
		mutex_lock(&cpu_mutex);
		for_each_online_cpu(cpu){
			per_cpu(pc.pc_uu_counter,cpu) = 0;
		}
		mutex_unlock(&cpu_mutex);
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
static unsigned storm_hook(const struct nf_hook_ops *ops,
	struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{       
	if(!skb){
            return NF_ACCEPT;
        }

        if(skb->dev == sc_dev.dev){
	    /*Broadcast processing*/
            if(skb->pkt_type == PACKET_BROADCAST && (sc_dev.t_type & TRAFFIC_TYPE_BROADCAST)){
                if(sc_dev.b_flag->b_flag == 1){
                    if(skb->tstamp - sc_dev.p_time->block_b_time <= 1 ){
                        printk(KERN_INFO "Broadcast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{
				sc_dev.p_counter->b_counter = total_cpu_packet(pcc);
				if((int)sc_dev.p_counter->b_counter <= low_threshold){
					sc_dev.b_flag->b_flag = 0;
					sc_dev.p_counter->b_counter = 0;
					initilize_cpu_counter(pcc);
                        		printk(KERN_INFO "One second passed.\n");
                        		printk(KERN_INFO "Broadcast blocking was unset.\n");
					return NF_DROP;
				}
				else{
					sc_dev.p_counter->b_counter = 0;
					sc_dev.p_time->block_b_time = skb->tstamp;
					initilize_cpu_counter(pcc);
					printk(KERN_INFO "Traffic flow exceed low threshold.\n");
					printk(KERN_INFO "One more minute are added.\n");
					return NF_DROP;
				}
                    }
                }
		sc_dev.p_counter->b_counter = total_cpu_packet(pcc);

                if(sc_dev.p_counter->b_counter == 1){
			sc_dev.p_counter->b_counter = 0;
                    	sc_dev.p_time->first_b_time = skb->tstamp;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->b_counter < threshold){
		    	sc_dev.p_counter->b_counter = 0;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->b_counter >= threshold){
                    if(skb->tstamp - sc_dev.p_time->first_b_time <= 1){
			initilize_cpu_counter(pcc);

                        sc_dev.p_counter->b_counter = 0;
                        sc_dev.b_flag->b_flag = 1;
                        sc_dev.p_time->block_b_time = skb->tstamp;

                        printk(KERN_INFO "Broadcast pakcet per second became higher that the threthold.\n");
                        printk(KERN_INFO "--------Broadcast blocking started--------\n");
                        printk(KERN_INFO "Broadcast packet was dropped .\n");

                        return NF_DROP;
                    }
                    else{
                        sc_dev.p_counter->b_counter = 1;
                        sc_dev.p_time->first_b_time = skb->tstamp;
                        return NF_ACCEPT;
                    }
                }
                else{
                    return NF_ACCEPT;
                }
            }

            /* Multicast processing */
            else if(skb->pkt_type == PACKET_MULTICAST && (sc_dev.t_type & TRAFFIC_TYPE_MULTICAST)){
                if(sc_dev.b_flag->m_flag == 1){
                    if(skb->tstamp - sc_dev.p_time->block_m_time <= 1){
                        printk(KERN_INFO "Multicast packet was dropped .\n");
                        return NF_DROP;
                    }
		    else{
				sc_dev.p_counter->m_counter = total_cpu_packet(pcc);
				if((int)sc_dev.p_counter->m_counter <= low_threshold){
					sc_dev.b_flag->m_flag = 0;
					sc_dev.p_counter->m_counter = 0;
					initilize_cpu_counter(pcc);

                        		printk(KERN_INFO "One second passed.\n");
                        		printk(KERN_INFO "Broadcast blocking was unset.\n");
					return NF_DROP;
				}
				else{
					sc_dev.p_counter->m_counter = 0;
					sc_dev.p_time->block_m_time = skb->tstamp;
					initilize_cpu_counter(pcc);

					printk(KERN_INFO "Traffic flow exceed low threshold.\n");
					printk(KERN_INFO "One more minute are added.\n");
					return NF_DROP;
				}
                    	}
                }
		sc_dev.p_counter->m_counter = total_cpu_packet(pcc);
		
                if(sc_dev.p_counter->m_counter == 1){
			sc_dev.p_counter->m_counter = 0;
                    	sc_dev.p_time->first_m_time = skb->tstamp;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->m_counter < threshold){
			sc_dev.p_counter->m_counter = 0;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->m_counter >= threshold){
                	if(skb->tstamp - sc_dev.p_time->first_m_time <= 1){
				sc_dev.p_counter->m_counter = 0;
                        	sc_dev.b_flag->m_flag = 1;
                        	sc_dev.p_time->block_m_time = skb->tstamp;
				initilize_cpu_counter(pcc);

                        	printk(KERN_INFO "Multicast pakcet per second became higher that the threthold.\n");
                        	printk(KERN_INFO "--------Multicast blocking started--------\n");
                        	printk(KERN_INFO "Multicast packet was dropped .\n");

                        	return NF_DROP;
                    		}
                	else{
				sc_dev.p_counter->m_counter = 1;
                        	sc_dev.p_time->first_m_time = skb->tstamp;
                        	return NF_ACCEPT;
                    	}
                }
            }

	    /*Unknown_Unicast processing*/
	    else if((route4_input(skb) == -1 ) && (sc_dev.t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)){
		if(sc_dev.b_flag->uu_flag == 1){
                    if(skb->tstamp - sc_dev.p_time->block_uu_time <= 1){
                        printk(KERN_INFO "Unknown_unicast packet was dropped .\n");
                        return NF_DROP;
                    }
		    else{
				sc_dev.p_counter->uu_counter = total_cpu_packet(pcc);
				if((int)sc_dev.p_counter->uu_counter <= low_threshold){
					sc_dev.b_flag->uu_flag = 0;
					sc_dev.p_counter->uu_counter = 0;
					initilize_cpu_counter(pcc);

                        		printk(KERN_INFO "One second passed.\n");
                        		printk(KERN_INFO "Broadcast blocking was unset.\n");
					return NF_DROP;
				}
				else{
					sc_dev.p_counter->uu_counter = 0;
					sc_dev.p_time->block_uu_time = skb->tstamp;
					initilize_cpu_counter(pcc);

					printk(KERN_INFO "Traffic flow exceed low threshold.\n");
					printk(KERN_INFO "One more minute are added.\n");
					return NF_DROP;
				}
                    	}
                }
		sc_dev.p_counter->uu_counter = total_cpu_packet(pcc);
		
                if(sc_dev.p_counter->uu_counter == 1){
			sc_dev.p_counter->uu_counter = 0;
                    	sc_dev.p_time->first_uu_time = skb->tstamp;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->uu_counter < threshold){
			sc_dev.p_counter->uu_counter = 0;
                    	return NF_ACCEPT;
                }
                else if((int)sc_dev.p_counter->uu_counter >= threshold){
                	if(skb->tstamp - sc_dev.p_time->first_uu_time <= 1){
				sc_dev.p_counter->uu_counter = 0;
                        	sc_dev.b_flag->uu_flag = 1;
                        	sc_dev.p_time->block_uu_time = skb->tstamp;
				initilize_cpu_counter(pcc);

                        	printk(KERN_INFO "Multicast pakcet per second became higher that the threthold.\n");
                        	printk(KERN_INFO "--------Multicast blocking started--------\n");
                        	printk(KERN_INFO "Multicast packet was dropped .\n");

                        	return NF_DROP;
                    		}
                	else{
				sc_dev.p_counter->uu_counter = 1;
                        	sc_dev.p_time->first_uu_time = skb->tstamp;
                        	return NF_ACCEPT;
                    	}
                }
	    }
            else{
                return NF_ACCEPT;
            }
        }
        else{
            return NF_ACCEPT;
        }
}

const static struct nf_hook_ops nf_ops_storm __read_mostly = {
	.hook = storm_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_IP_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
};
    
static int 
__init stctl_init_module(void)
{       
        int ret = 0;

	memset(&sc_dev,0,sizeof(sc_dev));
	memset(&pcc,0,sizeof(pcc));
	/*sc_dev.t_type = (TRAFFIC_TYPE_BROADCAST | TRAFFIC_TYPE_MULTICAST | TRAFFIC_TYPE_UNKNOWN_UNICAST);*/
	sc_dev.dev = dev_get_by_name(&init_net,d_name);

        ret = nf_register_hooks(&(nf_ops_storm));
        if(ret){
                printk(KERN_DEBUG "failed to register hook.\n");
        }
	printk (KERN_INFO "storm_control module is loaded\n");

	if(strcmp(traffic_type,"broadcast") == 0){
		sc_dev.t_type = TRAFFIC_TYPE_BROADCAST 
            	printk(KERN_INFO "Control target is broadcast.\n");
        }
        else if(strcmp(traffic_type,"multicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_MULTICAST
            	printk(KERN_INFO "Control target is multicast.\n");
        }
	else if(strcmp(traffic_type,"unknown_unicast")==0){
		sc_dev.t_type = TRAFFIC_TYPE_UNKNOWN_UNICAST
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

	/*free_percpu(storm_counter);*/
	nf_unregister_hook(&(nf_ops_storm));

    	printk(KERN_INFO "Storm control module was Removed.\n");
}
module_exit(stctl_exit_module);
