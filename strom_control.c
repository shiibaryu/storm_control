#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/if_packet.h>

MODULE_LICENSE("Debian");
MODULE_AUTHOR("siiba");
MODULE_INFO("strom control module");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");

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

static struct nf_hook_ops nf_ops_storm;

/* get the interface user specified */
/*struct net_device *get_netdev()
{
    struct net_device *dev:

    read_lock(&dev_base_lock);
    for_each_netdev(&init_net,dev){
        if(strcmp(dev_name,dev->name)==0){
            return dev;
        }
    }
    read_unlock(&dev_base_lock);

}*/

/*the function hooks by incoming packet*/
const static unsigned storm_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{       
        static int b_count=0; /* the counter for broadcast*/
        static int m_conunt=0; /* the counter for multicast*/
        static int b_flag = 0; /*the flag that represents whether broadcast blocking is on or not*/
        static int m_flag = 0; /*the flag that represents whether multicast blocking is on or not*/
        static ktime_t first_b_time; /*the time at when first broadcast packet arrived*/
        static ktime_t first_m_time; /*the time at when first multidcast packet arrived*/
        static ktime_t block_b_time; /*the time when broadcast packet blocking started*/
        static ktime_t block_m_time; /*the time when multicast packet blocking started*/
        struct net_device *n_dev;

        if(!skb){
            return NF_ACCEPT;
        }

        if(strcmp(skb->dev->name,dev_name)==0){
            /* Broadcast processing */
            if(skb->pkt_type == PACKET_BROADCAST && traffic_type == "broadcast"){
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

        nf_ops_storm.hook = storm_hook;
        nf_ops_storm.pf = PF_INET;
        nf_ops_storm.hooknum = NF_IP_PRE_ROUTING;
        nf_ops_storm.priority = NF_IP_PRI_FIRST;                

        printk(KERN_INFO "Storm control module was inserted.");

        if(traffic_type == "broadcast"){
            printk(KERN_INFO "storm control for broadcast was set.");
        }
        else if(traffic_type == "multicast"){
            printk(KERN_INFO "storm control for multicast was set.");
        }
        else{
            printk(KERN_DEBUG "this traffic type isn't registered.");
        }

        ret = nf_register_net_hook(NULL,&nf_ops_storm);
        if(ret < 0){
                printk(KERN_DEBUG "this traffic type wasn't registered.");
        }

        return 0;
}

static void exit_module()
{
    nf_unregister_net_hook(NULL,&nf_ops_storm);

    printk(KERN_INFO "Storm control module was Removed.");
}
