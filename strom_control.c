/* 
 * Traffic storm control module for linux kernel
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
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

/* the interface name a user can specify*/
static char *dev_name;
module_param(dev_name,charp,0660);

/* the traffic type a user want to control storm*/
static char *traffic_type;
module_param(traffic_type,charp,0660);

/* bps or pps*/
/*
static char *per_second;
module_param(per_second,charp,0660);
*/

/* the threthhold that set the traffic limit*/
static int *threshold;
module_param(threshold,int,0660);

/* the the threthold for low level limit*/
static int *low_threshold;
module_param(low_threshold,int,0660);

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004

typedef enum { false = 0, true } bool_t;

struct packet_counter{
	int b_counter; /* the counter for broadcast*/
	int m_counter; /* the counter for multicast*/
	int uu_counter; /* the counter for unknown unicast*/
};

struct block_flag{
	bool_t b_flag; /*the flag that represents whether broadcast blocking is on or not*/
	bool_t m_flag; /*the flag that represents whether multicast blocking is on or not*/
	bool_t uu_flag; /*the flag that represents whether unknonw unicast blocking is on or not*/
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
	int pc_b_counter; /* per cpu bloadcast packet counter */
	int pc_m_counter; /* per cpu multicast packet counter */
	int pc_uu_counter; /* per cpu unknown unicast packet counter */
	u16 t_type; /* user specified traffic type*/
};

const static struct nf_hook_ops nf_ops_storm = {
	.hook = storm_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_IP_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,                
};

DEFINE_PER_CPU(struct storm_control_dev,scd);


/*
unknown unicast対応・ロック
構造体の値、特にカウンター、フラグの保持
bps対応
*/

/*the function hooks incoming packet*/
static unsigned storm_hook(const struct nf_hook_ops *ops,
	struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{       
	int cpu;

	if(!skb){
            return NF_ACCEPT;
        }

	/*struct net *net;*/
	struct strom_control_dev *sc_dev = kmalloc(sizeof(struct storm_control_dev),GFP_KERNEL);
	if(!sc_dev){
		kfree(sc_dev);
		return -ENOMEM;
	}

	sc_dev->t_type = (TRAFFIC_TYPE_BROADCAST | TRAFFIC_TYPE_MULTICAST | TRAFFIC_TYPE_UNKNOWN_UNICAST);
	sc_dev->dev = dev_get_by_name(dev_name);/*dev_get_by_name(net,dev_name);*/

        if(skb->dev == sc_dev->dev){
	    /*Broadcast processing*/
            if(skb->pkt_type == PACKET_BROADCAST && (sc_dev->t_type & traffic_type)){
                if(sk_dev->b_flag->b_flag = true){
                    if(skb->tstamp.off_sec - sc_dev->p_time->block_b_time <= 1 ){
                        printk(KERN_INFO "Broadcast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{
				this_cpu_inc(scd.pc_b_counter);
				for_each_online_cpu(cpu){
					sc_dev->p_counter->b_counter += per_cpu(scd.pc_b_counter,cpu);
				}
				if(sc_dev->p_counter->b_counter <= low_threshold){
					sc_dev->b_flag->b_flag = false;
					sc_dev->p_counter->b_counter = 0;
					for_each_online_cpu(cpu){
						per_cpu(scd.pc_b_counter,cpu) = 0;
					}
                        		printk(KERN_INFO "One second passed.\n");
                        		printk(KERN_INFO "Broadcast blocking was unset.\n");
					return NF_DROP;
				}
				else{
					sc_dev->p_counter->b_counter = 0;
					sc_dev->p_time->block_b_time = skb->tstamp.off_sec;
					for_each_online_cpu(cpu){
						per_cpu(scd.pc_b_counter,cpu) = 0;
					}

					printk(KERN_INFO "Traffic flow exceed low threshold.\n");
					printk(KERN_INFO "One more minute are added.\n");
					return NF_DROP;
				}
                    }
                }

		this_cpu_inc(scd.pc_b_counter);
		for_each_online_cpu(cpu){
			sc_dev->p_counter->b_counter += per_cpu(scd.pc_b_counter,cpu);
		}

                if(sc_dev->p_counter->b_counter == 1){
			sc_dev->p_counter->b_counter = 0;
                    	sc_dev->p_time->first_b_time = skb->tstamp.off_sec;
                    	return NF_ACCEPT;
                }
                else if(sc_dev->p_counter->b_counter < threshold){
		    	sc_dev->p_counter->b_counter = 0;
                    	return NF_ACCEPT;
                }
                else if(sc_dev->p_counter->b_counter >= threshold){
                    if(skb->tstamp.off_sec - sc_dev->p_time->first_b_time <= 1){
			for_each_online_cpu(cpu){
				per_cpu(scd.pc_b_counter,cpu) = 0;
			}
                        sc_dev->p_counter->b_counter = 0;
                        sc_dev->b_flag->b_flag = true;
                        sc_dev->p_time->block_b_time = skb->tstamp.off_sec;

                        printk(KERN_INFO "Broadcast pakcet per second became higher that the threthold.\n");
                        printk(KERN_INFO "--------Broadcast blocking started--------\n");
                        printk(KERN_INFO "Broadcast packet was dropped .\n");

                        return NF_DROP;
                    }
                    else{
                        sc_dev->p_counter->b_counter = 1;
                        sc_dev->p_time->first_b_time = skb->tstamp.off_sec;
                        return NF_ACCEPT;
                    }
                }
                else{
                    return NF_ACCEPT;
                }
            }

            /* Multicast processing */
            else if(skb->pkt_type == TRAFFIC_TYPE_UNKNOWN_UNICAST && (sc_dev->t_type & traffic_type)){
                if(sc_dev->b_flag->m_flag == true){
                    if(skb->tstamp.off_sec - sc_dev->p_time->block_m_time <= 1){
                        printk(KERN_INFO "Multicast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{
                        sc_dev->b_flag->m_flag = false;
                        printk(KERN_INFO "One second passed.");
                        printk(KERN_INFO "Multicast blocking was unset.");
                    }
                }

		this_cpu_inc(scd.pc_m_counter);
		
		for_each_online_cpu(cpu){
			sc_dev->p_counter->m_counter += per_cpu(scd.pc_m_counter,cpu);
		}
                if(sc_dev->p_counter->m_counter == 1){
			sc_dev->p_counter->m_counter = 0;
                    	sc_dev->p_time->first_m_time = skb->tstamp.off_sec;
                    	return NF_ACCEPT;
                }
                else if(sc_dev->p_counter->m_counter < threshold){
			sc_dev->p_counter->m_counter = 0;
                    	return NF_ACCEPT;
                }
                else if(sc_dev->p_counter->m_counter >= threshold){
                	if(skb->tstamp.off_sec - sc_dev->p_time->first_m_time <= 1){
				for_each_online_cpu(cpu){
					per_cpu(scd.pc_m_counter,cpu) = 0;
					}
				sc_dev->p_counter->m_counter = 0;
                        	sc_dev->b_flag->m_flag = true;
                        	sc_dev->p_time->block_m_time = skb->tstamp.off_sec;

                        	printk(KERN_INFO "Multicast pakcet per second became higher that the threthold.\n");
                        	printk(KERN_INFO "--------Multicast blocking started--------\n");
                        	printk(KERN_INFO "Multicast packet was dropped .\n");

                        	return NF_DROP;
                    		}
                	else{
				sc_dev->p_counter->m_counter = 1
                        	sc_dev->p_time->first_m_time = skb->tstamp.off_sec;
                        	return NF_ACCEPT;
                    	}
                }
            }
	    else if( (ip_route_input(skb,,,,skb->dev))&& (sc_dev->t_type & traffic_type))
	    /*else if(skb->dev->dev_addr != sc_dev->dev->dev_addr)*/
	    /*else if (&& ( sc_dev->t_type & traffictype)) {
		if(m_flag == true){
                    if(skb->tstamp.off_sec - block_m_time <= 1){
                        printk(KERN_INFO "Multicast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{
                        m_flag = false;
                        printk(KERN_INFO "One second passed.");
                        printk(KERN_INFO "Multicast blocking was unset.");
                    }
                }

                m_counter += 1;
                if(m_counter == 1){
                    first_m_time = skb->tstamp.off_sec;
                    return NF_ACCEPT;
                }
                else if(m_counter < threshold){
                    return NF_ACCEPT;
                }
                else if(m_counter >= threshold){
                    if(skb->tstamp.off_sec - first_m_time <= 1){
                        m_counter = 0;
                        m_flag = true;
                        block_m_time = skb->tstamp.off_sec;

                        printk(KERN_INFO "Multicast pakcet per second became higher that the threthold.\n");
                        printk(KERN_INFO "--------Multicast blocking started--------\n");
                        printk(KERN_INFO "Multicast packet was dropped .\n");

                        return NF_DROP;
                    }
                    else{
                        first_m_time = skb->tstamp.off_sec;
                        m_counter = 1;
                        return NF_ACCEPT;
                    }
                }
		    
	    }*/
	    
            /* Any packets other that above can be passed */
            else{
                return NF_ACCEPT;
            }
        }

        else{
            return NF_ACCEPT;
        }
}
    
static int init_module()
{       
        int ret;

        printk(KERN_INFO "Storm control module was inserted.\n");

        if(traffic_type == "broadcast"){
		traffic_type = TRAFFIC_TYPE_BROADCAST;
            	printk(KERN_INFO "storm control for broadcast was set.\n");
        }
        else if(traffic_type == "multicast"){
	    	traffic_type = TRAFFIC_TYPE_MULTICAST;
            	printk(KERN_INFO "storm control for multicast was set.\n");
        }
	else if(traffic_type == "unknownunicast"){
		traffic_type == TRAFFIC_TYPE_UNKNOWN_UNICAST;
		printk(KERN_INFO "storm control for unknown_unicast was set.\n");
	}
        else{
            printk(KERN_DEBUG "this traffic type could not be registered.\n");
        }

        ret = nf_register_net_hook(NULL,&nf_ops_storm);
        if(ret < 0){
                printk(KERN_DEBUG "this traffic type wasn't registered.\n");
        }

        return 0;
}

static void exit_module()
{
	kfree(sc_dev);
	free_percpu(storm_counter);
	nf_unregister_net_hook(NULL,&nf_ops_storm);

    	printk(KERN_INFO "Storm control module was Removed.\n");
}

MODULE_LICENSE("Debian");
MODULE_AUTHOR("siibaaaaaaaaaaaaaa");
MODULE_INFO("strom control module");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");
