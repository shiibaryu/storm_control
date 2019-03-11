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

/* the interface name a user can specify*/
static char *dev_name;
module_param(dev_name,charp,0660);

/* the traffic type a user want to control storm*/
static char *traffic_type;
module_param(traffic_type,charp,0660);

/* the threthhold that set the traffic limit*/
static int *threshold;
module_param(threshold,int,0660);

/* the the threthold for low level limit*/
static int *low_threshold;
module_param(low_threshold,int,0660);

const static struct nf_hook_ops nf_ops_storm = {
	.hook = storm_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_IP_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,                
};

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004

struct storm_control_dev{
	struct net_dev *dev;
	int threshold; /* threshold to start blocking bum packet*/
	int low_threshold; /* threshold to stop blocking specified packet*/
	int b_count; /* the counter for broadcast*/
	int m_conunt; /* the counter for multicast*/
	int b_flag; /*the flag that represents whether broadcast blocking is on or not*/
	int m_flag; /*the flag that represents whether multicast blocking is on or not*/
	ktime_t first_b_time; /*the time at when first broadcast packet arrived*/
	ktime_t first_m_time; /*the time at when first multidcast packet arrived*/
	ktime_t block_b_time; /*the time when broadcast packet blocking started*/
	ktime_t block_m_time; /*the time when multicast packet blocking started*/
	u16 t_type; /* user specified traffic type*/
};

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
	/*struct net *net;*/
	struct strom_control_dev *sc_dev = malloc(sizeof(struct storm_control_dev));
	if(sc_dev == NULL){
		printk(KERN_DEBUG "Failed to memory allocation.\n");
		return -1;
	}

	sc_dev->t_type = (TRAFFIC_TYPE_UNKNOWN_UNICAST | TRAFFIC_TYPE_BROADCAST | TRAFFIC_TYPE_MULTICAST);
	sc_dev->dev = dev_get_by_name(dev_name);/*dev_get_by_name(net,dev_name);*/

        if(skb->dev == sc_dev->dev){
            /* Broadcast processing */
            if(skb->pkt_type == PACKET_BROADCAST && (sc_dev->t_type & traffic_type)){
                if(b_flag = 1){
                    if(skb->tstamp.off_sec - block_b_time <= 1 ){
                        printk(KERN_INFO "Broadcast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{

                        b_flag = 0;
                        printk(KERN_INFO "One second passed.");
                        printk(KERN_INFO "Broadcast blocking was unset.");
                    }
                }

                b_count += 1;

                if(b_count == 1){
                    first_b_time = skb->tstamp.off_sec;
                    return NF_ACCEPT;
                }
                else if(b_count < threshold){
                    return NF_ACCEPT;
                }
                else if(b_count >= threshold){
                    if(skb->tstamp.off_sec - first_b_time <= 1){
                        b_count = 0;
                        b_flag = 1;
                        block_b_time = skb->skb->tstamp.off_sec;

                        printk(KERN_INFO "Broadcast pakcet per second became higher that the threthold.\n");
                        printk(KERN_INFO "--------Broadcast blocking started--------\n");
                        printk(KERN_INFO "Broadcast packet was dropped .\n");

                        return NF_DROP;
                    }
                    else{
                        b_count = 1;
                        first_b_time = skb->tstamp.off_sec;
                        return NF_ACCEPT;
                    }
                }
                else{
                    return NF_ACCEPT;
                }
            }

            /* Multicast processing */
            else if(skb->pkt_type == PACKET_MULTICAST && traffic_type == "multicast"){
                if(m_flag == 1){
                    if(skb->tstamp.off_sec - block_m_time <= 1){
                        printk(KERN_INFO "Multicast packet was dropped .\n");
                        return NF_DROP;
                    }
                    else{
                        m_flag = 0;
                        printk(KERN_INFO "One second passed.");
                        printk(KERN_INFO "Multicast blocking was unset.");
                    }
                }

                m_count += 1;
                if(m_count == 1){
                    first_m_time = skb->tstamp.off_sec;
                    return NF_ACCEPT;
                }
                else if(m_count < threshold){
                    return NF_ACCEPT;
                }
                else if(m_count >= threshold){
                    if(skb->tstamp.off_sec - first_m_time <= 1){
                        m_count = 0;
                        m_flag = 1;
                        block_m_time = skb->tstamp.off_sec;

                        printk(KERN_INFO "Multicast pakcet per second became higher that the threthold.\n");
                        printk(KERN_INFO "--------Multicast blocking started--------\n");
                        printk(KERN_INFO "Multicast packet was dropped .\n");

                        return NF_DROP;
                    }
                    else{
                        first_m_time = skb->tstamp.off_sec;
                        m_count = 1;
                        return NF_ACCEPT;
                    }
                }
            }

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
    nf_unregister_net_hook(NULL,&nf_ops_storm);

    printk(KERN_INFO "Storm control module was Removed.\n");
}

MODULE_LICENSE("Debian");
MODULE_AUTHOR("siibaaaaaaaaaaaaaa");
MODULE_INFO("strom control module");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");
