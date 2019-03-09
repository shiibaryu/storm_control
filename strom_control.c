#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ktime.h>
#include <linux/if_packet.h>

MODULE_LICENSE("Debian"):
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
static unsigned storm_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff*))
{       
        /* the counter for broadcast*/
        static int b_count=0; 
        /* the counter for multicast*/
        static int m_conunt=0;
        /*the flag that represents whether broadcast blocking is on or not*/
        static int b_flag = 0;
        /*the flag that represents whether multicast blocking is on or not*/
        static int m_flag = 0;
        /*the time at when first broadcast packet arrived*/
        static ktime_t first_b_time;
        /*the time at when first multidcast packet arrived*/
        static ktime_t first_m_time;
        /*the time when broadcast packet blocking started*/
        static ktime_t block_b_time;
        /*the time when multicast packet blocking started*/
        static ktime_t block_m_time;
        struct net_device *n_dev;

        if(!skb){
            return NF_ACCEPT;
        }

        if(strcmp(skb->dev->name,dev_name)==0){
            switch (skb->pkt_type){

            case PACKET_BROADCAST:
                if(b_flag = 1){
                    if(skb->tstamp.off_sec - block_b_time <= 1 ){
                        return NF_DROP;
                    }
                    else{
                        b_flag = 0;
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
                break;
        
            case PACKET_MULTICAST:
                if(m_flag == 1){
                    if(skb->tstamp.off_sec - block_m_time <= 1){
                        return NF_DROP;
                    }
                    else{
                        m_flag = 0;
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
                        return NF_DROP;
                    }
                    else{
                        first_m_time = skb->tstamp.off_sec;
                        m_count = 1;
                        return NF_ACCEPT;
                    }
                }
                break;

            default:
                return NF_ACCEPT;
                break;
            }
        else{
            return NF_ACCEPT;
        }
        }
}
    
static int init_module()
{       
        int ret;
        nf_ops_storm.hook = storm_hook;
        nf_ops_storm.pf = PF_INET 
        nf_ops_storm.hooknum = NF_IP_PRE_ROUTING;
        nf_ops_storm.priority = NF_IP_PRI_FIRST;                

        printk(KERN_INFO "Storm control module was inserted.");

        ret = nf_register_net_hook(NULL,&nf_ops_storm);
        if(ret < 0){
                pr_err("failed to regsiter netfilter hook.\n");
        }

        return 0;
}

static void exit_module()
{
    nf_unregister_net_hook(NULL,&nf_ops_storm);

    printk(KERN_INFO "Storm control module was Removed.");
}
