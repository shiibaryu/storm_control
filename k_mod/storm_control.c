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
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/percpu.h>
#include <linux/ip.h>
#include <linux/cpumask.h>
#include <linux/percpu-defs.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>
#include <net/route.h>

#include "storm.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("siibaa");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004
#define FLAG_UP				0x0001
#define FLAG_DOWN			0x0002
#define PPS				0x0001
#define BPS			        0x0002
#define TIMER_TIMEOUT_SECS    	        1

/* per netnamespace parameters*/
static unsigned int storm_net_id;
static int descriptor;

struct storm_net{
	struct net *net;
	struct list_head if_list;
};

struct storm_control_dev{
	struct net *net;
	struct list_head list;
	struct rcu_head	 rcu;

	struct storm_info s_info;
	struct net_device *dev;
	int __percpu *pps;
	unsigned int __percpu *bps;
	int if_descriptor;
	int pps_checker;
	unsigned int bps_checker;
};

struct timer_data{
	struct timer_list timer;
	int timer_descriptor;
};
static struct timer_data sc_timer;

/*mutext for checking per_cpu variable*/
static DEFINE_MUTEX(cpu_mutex);

/* a prototype for ip_route_input */
int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin);

static rx_handler_result_t sc_rx_handler(struct sk_buff **pskb);

static struct storm_control_dev *storm_find_if(struct storm_net *storm,char *dev)
{
	struct storm_control_dev *sc_dev;

	list_for_each_entry_rcu(sc_dev,&storm->if_list,list){
		if(strncmp(sc_dev->s_info.if_name,dev,STORM_DEVNAME_MAX)==0){
			return sc_dev;
		}
	}

	return NULL;
}

static int storm_add_if(struct storm_net *storm,struct storm_info *s_info)
{
	int ret;
        bool found = false;
	struct net *if_net;
	struct storm_control_dev *sc_dev,*next;

	sc_dev = (struct storm_control_dev *)kmalloc(sizeof(struct storm_control_dev),
									GFP_KERNEL);
	if(!sc_dev){
		return -ENOMEM;
	}

	memset(sc_dev,0,sizeof(*sc_dev));
	sc_dev->s_info = *s_info;

	if_net = get_net(&init_net);
	if (IS_ERR(if_net)) {
		pr_debug("%s: invalid netns\n", __func__);
		kfree(sc_dev);
		return PTR_ERR(if_net);
	}
	sc_dev->net = if_net;
	sc_dev->dev = dev_get_by_name(&init_net,sc_dev->s_info.if_name);
	if (!sc_dev->dev){
		return -1;
	}

	if(sc_dev->s_info.traffic_type & TRAFFIC_TYPE_BROADCAST){
            	printk(KERN_INFO "Control target is broadcast.\n");
        }
        else if(sc_dev->s_info.traffic_type & TRAFFIC_TYPE_MULTICAST){
            	printk(KERN_INFO "Control target is multicast.\n");
        }
	else if(sc_dev->s_info.traffic_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		printk(KERN_INFO "Control target is unknown_unicast.\n");
	}
        else{
            printk(KERN_INFO "This traffic type could not be registered.\n");
        }

	sc_dev->if_descriptor = descriptor;
	descriptor += 1;

	if(sc_dev->s_info.pb_type & PPS){
		sc_dev->pps = alloc_percpu(int);
		if(!sc_dev->pps){
			kfree(sc_dev);
			return -1;
		}
	}
	else if(sc_dev->s_info.pb_type & BPS){
		sc_dev->bps = alloc_percpu(unsigned int);
		if(!sc_dev->bps){
			kfree(sc_dev);
			return -1;
		}
	}

	list_for_each_entry_rcu(next,&storm->if_list,list){
		if(sc_dev->dev == next->dev){
			found = true;
			break;
		}
	}


	if(found){
		__list_add_rcu(&sc_dev->list,next->list.prev,&next->list);
	}
	else{
		list_add_tail_rcu(&sc_dev->list,&storm->if_list);
	}
      printk(KERN_INFO "scandal baby!");
        ret = netdev_rx_handler_register(sc_dev->dev,sc_rx_handler,sc_dev);
        if(ret < 0){
                printk(KERN_INFO "failed to register netdev_rx_handler.\n");
        }
        
	return 0;
}
static void storm_del_if(struct storm_control_dev *sc_dev)
{
	put_net(sc_dev->net);
        netdev_rx_handler_unregister(sc_dev->dev);
	dev_put(sc_dev->dev);
	if(sc_dev->s_info.pb_type & PPS){
		free_percpu(sc_dev->pps);
	}
	else if(sc_dev->s_info.pb_type & BPS){
		free_percpu(sc_dev->bps);
	}
	
	list_del_rcu(&sc_dev->list);
	kfree_rcu(sc_dev,rcu);
}

static __net_init int storm_init_net(struct net *net)
{
	struct storm_net *storm = net_generic(net,storm_net_id);

	storm->net = net;
	INIT_LIST_HEAD(&storm->if_list);

	return 0;
}

static __net_exit void storm_exit_net(struct net *net)
{
	struct storm_net *storm = net_generic(net,storm_net_id);
	struct storm_control_dev *sc_dev,*next;

	rcu_read_lock();

	list_for_each_entry_safe(sc_dev,next,&storm->if_list,list){
                netdev_rx_handler_unregister(sc_dev->dev);
		storm_del_if(sc_dev);
	}

	rcu_read_unlock();

	return;
}

static struct pernet_operations storm_net_ops = {
	.init = storm_init_net,
	.exit = storm_exit_net,
	.id   = &storm_net_id,
	.size = sizeof(struct storm_net),
};

/* Generic Netlink implementation */
static int storm_nl_add_if(struct sk_buff *skb, struct genl_info * info);
static int storm_nl_del_if(struct sk_buff *skb, struct genl_info * info);
static int storm_nl_show_if(struct sk_buff *skb, struct netlink_callback *cb);

static struct nla_policy storm_nl_policy[STORM_ATTR_MAX + 1] = {
	[STORM_ATTR_IF] = { .type = NLA_BINARY,
	                    .len = sizeof(struct storm_info)},
};

static struct genl_ops storm_nl_ops[] = {
	{
		.cmd	= STORM_CMD_ADD_IF,
		.doit	= storm_nl_add_if,
		.policy	= storm_nl_policy,
		.flags	= GENL_ADMIN_PERM,
    	},
    	{
		.cmd	= STORM_CMD_DEL_IF,
		.doit	= storm_nl_del_if,
		.policy	= storm_nl_policy,
		.flags	= GENL_ADMIN_PERM,
    	},
	{
		.cmd 	= STORM_CMD_SHOW_IF,
		.dumpit = storm_nl_show_if,
		.policy = storm_nl_policy,
	},
};

static struct genl_family storm_nl_family = {
	.name		= STORM_GENL_NAME,
	.version	= STORM_GENL_VERSION,
	.maxattr	= STORM_ATTR_MAX,
	.hdrsize	= 0,
	.netnsok	= true,
	.ops		= storm_nl_ops,
        .n_ops      	= ARRAY_SIZE(storm_nl_ops),
	.module		= THIS_MODULE,
};


static int storm_nl_add_if(struct sk_buff *skb, struct genl_info *info)
{
	int ret;
	struct net *net = sock_net(skb->sk);
	struct storm_net *storm = net_generic(net,storm_net_id);
	struct storm_control_dev *sc_dev;
	struct storm_info s_info;

	if (!info->attrs[STORM_ATTR_IF]){
		return -EINVAL;
	}

	nla_memcpy(&s_info,info->attrs[STORM_ATTR_IF],sizeof(s_info));

	sc_dev = storm_find_if(storm,s_info.if_name);
	if(sc_dev){
		return -EEXIST;
	}

	ret = storm_add_if(storm,&s_info);
	if(ret < 0){
		return ret;
	}

	return 0;

}

static int storm_nl_del_if(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = sock_net(skb->sk);
	struct storm_net *storm = net_generic(net,storm_net_id);
	struct storm_control_dev *sc_dev;
	struct storm_info s_info;

	if (!info->attrs[STORM_ATTR_IF]){
		return -EINVAL;
	}

	nla_memcpy(&s_info,info->attrs[STORM_ATTR_IF],sizeof(s_info));

	sc_dev = storm_find_if(storm,s_info.if_name);
	if(!sc_dev){
		return -ENOENT;
	}

	storm_del_if(sc_dev);

	return 0;
}

static int storm_nl_send_if(struct sk_buff *skb, u32 portid, u32 seq,
			    int flags, struct storm_control_dev *sc_dev)
{
	void *hdr;
	struct storm_info s_info;

	hdr = genlmsg_put(skb, portid, seq, &storm_nl_family, flags,
			  STORM_CMD_SHOW_IF);

	if (!hdr){
		return -EMSGSIZE;
	}

	s_info = sc_dev->s_info;

	if (nla_put(skb,STORM_ATTR_IF, sizeof(s_info), &s_info)){
		goto nla_put_failure;
	}

	genlmsg_end(skb, hdr);

	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int storm_nl_show_if(struct sk_buff *skb, struct netlink_callback *cb)
{
	int ret, idx, cnt;
	struct storm_net *storm = net_generic(sock_net(skb->sk),storm_net_id);
	struct storm_control_dev *sc_dev;

	cnt = 0;
	idx = cb->args[0];
	
	list_for_each_entry_rcu(sc_dev, &storm->if_list, list) {
		if (idx > cnt) {
			cnt ++;
			continue;
		}
		ret = storm_nl_send_if(skb, NETLINK_CB(cb->skb).portid,
				       cb->nlh->nlmsg_seq, NLM_F_MULTI,sc_dev);
		if (ret < 0){
			return ret;
		}
		break;
	}

	cb->args[0] = cnt + 1;

	return skb->len;
}


static int pps_total_cpu_packet(int  __percpu *pps)
{
	int cpu=0;
	int total_packet = 0;

	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		total_packet += *per_cpu_ptr(pps,cpu);
	}
	mutex_unlock(&cpu_mutex);

	return total_packet;
}

static unsigned int bps_total_cpu_bit(unsigned int  __percpu *bps)
{
	int cpu=0;
	unsigned int total_bit = 0;

	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		total_bit += *per_cpu_ptr(bps,cpu);
	}
	mutex_unlock(&cpu_mutex);

	return total_bit;
}

static void initialize_pps_counter(int __percpu *pps)
{
	int cpu=0;

	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		*per_cpu_ptr(pps,cpu) = 0;
	}
	mutex_unlock(&cpu_mutex);
}

static void initialize_bps_counter(unsigned int __percpu *bps)
{
	int cpu=0;

	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		*per_cpu_ptr(bps,cpu) = 0;
	}
	mutex_unlock(&cpu_mutex);
}

static void pps_threshold_check(struct storm_control_dev *sc_dev){
	if(sc_dev->pps_checker >= sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
		sc_dev->s_info.drop_flag = FLAG_UP;
		sc_dev->pps_checker = 0;
		initialize_pps_counter(sc_dev->pps);
		mod_timer(&sc_timer.timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	/*printk(KERN_INFO "Packet per second was more than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "--------Blocking started at %s.--------\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Packet was dropped at %s.\n",sc_dev->s_info.if_name);*/
    	}
    else if(sc_dev->pps_checker < sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
	    	sc_dev->s_info.first_flag = FLAG_UP;
		sc_dev->pps_checker = 0;
		initialize_pps_counter(sc_dev->pps);
	    	/*printk(KERN_INFO "Packet per second was less than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Packet isn't blocked at %s.\n",sc_dev->s_info.if_name);*/
    	}	
    else if(sc_dev->pps_checker >= sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_UP)){
		sc_dev->pps_checker = 0;
	    	initialize_pps_counter(sc_dev->pps);
		mod_timer(&sc_timer.timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	/*printk(KERN_INFO "Packet per second was more than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Dropping packet continues at %s.\n",sc_dev->s_info.if_name);*/
    	}
    else if(sc_dev->pps_checker < sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_UP)){
	    	sc_dev->s_info.first_flag = FLAG_UP;
	    	sc_dev->s_info.drop_flag = FLAG_DOWN;
		sc_dev->pps_checker = 0;
		initialize_pps_counter(sc_dev->pps);
	    	/*printk(KERN_INFO "Packet per second was less than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "--------Packet blocking ended at %s .--------\n",sc_dev->s_info.if_name);*/
    	}
}

static void bps_threshold_check(struct storm_control_dev *sc_dev){
	if(sc_dev->bps_checker * 8 >= sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
		sc_dev->s_info.drop_flag = FLAG_UP;
		sc_dev->bps_checker = 0;
		initialize_bps_counter(sc_dev->bps);
		mod_timer(&sc_timer.timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	/*printk(KERN_INFO "Bit per second was more than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "--------Blocking started at %s.--------\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Packet was dropped at %s.\n",sc_dev->s_info.if_name);*/
    	}
    else if(sc_dev->bps_checker * 8 < sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
	    	sc_dev->s_info.first_flag = FLAG_UP;
		sc_dev->bps_checker = 0;
		initialize_bps_counter(sc_dev->bps);
	    	/*printk(KERN_INFO "Bit per second was less than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Packet isn't blocked at %s.\n",sc_dev->s_info.if_name);*/
    	}
    else if(sc_dev->bps_checker * 8 >= sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_UP)){
		sc_dev->bps_checker = 0;
	    	initialize_bps_counter(sc_dev->bps);
		mod_timer(&sc_timer.timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	/*printk(KERN_INFO "Bit per second was more than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "Dropping packet continues at %s.\n",sc_dev->s_info.if_name);*/
    	}
    else if(sc_dev->bps_checker * 8 < sc_dev->s_info.low_threshold && (sc_dev->s_info.drop_flag & FLAG_UP)){
		sc_dev->s_info.first_flag = FLAG_UP;
	    	sc_dev->s_info.drop_flag = FLAG_DOWN;
		sc_dev->bps_checker = 0;
		initialize_bps_counter(sc_dev->bps);
	    	/*printk(KERN_INFO "Bit per second was less than the threthold at %s.\n",sc_dev->s_info.if_name);
	    	printk(KERN_INFO "--------Blocking packet ended at %s.--------\n",sc_dev->s_info.if_name);*/
    	}
}

static void check_packet(struct timer_list *t)
{
	struct storm_control_dev *sc_dev;
	struct net *net;
        struct storm_net *storm;
	struct timer_data *sc_timer = from_timer(sc_timer,t,timer);

 	net = get_net(&init_net);
        storm = net_generic(net,storm_net_id);

        list_for_each_entry(sc_dev,&storm->if_list,list){
		if(sc_timer->timer_descriptor == sc_dev->if_descriptor){
		 	/*printk(KERN_INFO "--------One Second passed--------\n");*/
                	if(sc_dev->s_info.pb_type & PPS){
                        	sc_dev->pps_checker = pps_total_cpu_packet(sc_dev->pps);
                        	pps_threshold_check(sc_dev);
                	}
                	else if(sc_dev->s_info.pb_type & BPS){
                        	sc_dev->bps_checker = bps_total_cpu_bit(sc_dev->bps);
                        	bps_threshold_check(sc_dev);
                	}
       		}
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

/*the function hooked incoming packet*/
static rx_handler_result_t sc_rx_handler(struct sk_buff **pskb)
{       
        struct sk_buff *skb = *pskb;
	struct storm_control_dev *sc_dev = rcu_dereference(skb->dev->rx_handler_data);
	if(!skb){
            return NF_ACCEPT;
        }
        
        if((skb->pkt_type == PACKET_BROADCAST) && (sc_dev->s_info.traffic_type & TRAFFIC_TYPE_BROADCAST)){
	  	if((sc_dev->s_info.first_flag & FLAG_UP) && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
		        sc_dev->s_info.first_flag = FLAG_DOWN;
			/*printk(KERN_INFO "First broadcast packet was arrived at %s.\n",sc_dev->s_info.if_name);
				printk(KERN_INFO "One second timer started.\n");*/
					
			sc_timer.timer.expires = TIMER_TIMEOUT_SECS*HZ;
			sc_timer.timer_descriptor = sc_dev->if_descriptor;
			add_timer(&sc_timer.timer);

			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
				}
    		}
		else if(sc_dev->s_info.drop_flag & FLAG_DOWN){
			if(sc_dev->s_info.pb_type & PPS){
        			this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
				}
		}
       		else if(sc_dev->s_info.drop_flag & FLAG_UP){
			if(sc_dev->s_info.pb_type & PPS){
       				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_CONSUMED;
			}
			else if(sc_dev->s_info.pb_type & BPS){
       				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_CONSUMED;
			}
			else{
				return RX_HANDLER_CONSUMED;
			}
		}
		else{
				return RX_HANDLER_PASS;
			}
		}
 	else if(skb->pkt_type == PACKET_MULTICAST && (sc_dev->s_info.traffic_type & TRAFFIC_TYPE_MULTICAST)){
        	if((sc_dev->s_info.first_flag & FLAG_UP) && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
	        	sc_dev->s_info.first_flag = FLAG_DOWN;
					/*printk(KERN_INFO "First multicast packet was arrived at %s.\n",sc_dev->s_info.if_name);
					printk(KERN_INFO "--------One second timer started--------\n");*/

			sc_timer.timer.expires = TIMER_TIMEOUT_SECS*HZ;
                        sc_timer.timer_descriptor = sc_dev->if_descriptor;
                        add_timer(&sc_timer.timer);

			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
			}
	    			}
		else if(sc_dev->s_info.drop_flag & FLAG_DOWN){
			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
			}
		}
		else if(sc_dev->s_info.drop_flag & FLAG_UP){
			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_CONSUMED;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_CONSUMED;
			}
			else{
				return RX_HANDLER_CONSUMED;
			}
		}
		else{
			return RX_HANDLER_PASS;
		}
        }
	else if((route4_input(skb) == -1) && (sc_dev->s_info.traffic_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)){
		if((sc_dev->s_info.first_flag & FLAG_UP) && (sc_dev->s_info.drop_flag & FLAG_DOWN)){
	        	sc_dev->s_info.first_flag = FLAG_DOWN;
			/*printk(KERN_INFO "First unknown_unicast packet was arrived at %s.\n",sc_dev->s_info.if_name);
			printk(KERN_INFO "--------One second timer started--------\n");*/

			sc_timer.timer.expires = TIMER_TIMEOUT_SECS*HZ;
                        sc_timer.timer_descriptor = sc_dev->if_descriptor;
                        add_timer(&sc_timer.timer);
	
			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
			}
 		}
		else if(sc_dev->s_info.drop_flag & FLAG_DOWN){
			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_PASS;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_PASS;
			}
			else{
				return RX_HANDLER_PASS;
			}
		}
		else if(sc_dev->s_info.drop_flag & FLAG_UP){
			if(sc_dev->s_info.pb_type & PPS){
				this_cpu_inc(*sc_dev->pps);
				return RX_HANDLER_CONSUMED;
			}
			else if(sc_dev->s_info.pb_type & BPS){
				this_cpu_add(*sc_dev->bps,skb->len);
				return RX_HANDLER_CONSUMED;
			}
			else{
				return RX_HANDLER_CONSUMED;
			}
		}
		else{
			return RX_HANDLER_PASS;
		}
	}
	else{
		return RX_HANDLER_PASS;
	}

	return RX_HANDLER_PASS;
}
    
static int 
__init stctl_init_module(void)
{       
        int ret;
       	
	timer_setup(&sc_timer.timer,check_packet,0);

	ret = register_pernet_subsys(&storm_net_ops);
	if(ret){
		return ret;
	}

	ret = genl_register_family(&storm_nl_family);
	if(ret){
		printk(KERN_INFO "failed to register genl.\n");
		goto genl_register_failed;
	}

	printk(KERN_INFO "storm_control module was inserted.\n");

	return ret;

genl_register_failed:
	unregister_pernet_subsys(&storm_net_ops);


        return ret;
}
module_init(stctl_init_module);


static void 
__exit stctl_exit_module(void)
{	
	genl_unregister_family(&storm_nl_family);
	unregister_pernet_subsys(&storm_net_ops);
	del_timer(&sc_timer.timer);
    	printk(KERN_INFO "Storm control module was Removed.\n");
}
module_exit(stctl_exit_module);
