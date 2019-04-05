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

#include <storm.h>


MODULE_LICENSE("Debian");
MODULE_AUTHOR("siibaa");
MODULE_DESCRIPTION("This is a linux kernel module for strom control.");

#define TRAFFIC_TYPE_UNKNOWN_UNICAST    0x0001
#define TRAFFIC_TYPE_BROADCAST          0x0002
#define TRAFFIC_TYPE_MULTICAST          0x0004
#define FLAG_UP				0x0001
#define FLAG_DOWN			0x0002
#define PPS				0x0001
#define BPS			        0x0002
#define LEVEL				0x0004
#define TIMER_TIMEOUT_SECS    	        1

struct storm_net{
	struct net *net;
	struct list_head if_list;
};

struct pbl_counter{
	int __percpu *pps_counter;
	unsigned int __percpu *bps_counter;
};

struct pbl_checker {
	int pps_checker;
	unsigned int bps_checker;
};

struct storm_control_dev{
	struct net *net;
	struct list_head list;
	struct rcu_head	 rcu;

	struct net_device *dev;
	struct pbl_counter *pblc;
	struct pbl_checker pbl_chk;
	char *if_name;
	int threshold;
	int low_threshold;
	u16 pbl_type; /*flag to specify pps or bps or level*/
    	u16 d_flag; /*drop_flag*/
	u16 f_flag; /*first time or not*/
	u16 t_type; /* user specified traffic type*/
};
/*static struct storm_control_dev sc_dev;*/

static struct timer_list sc_timer;

/* per netnamespace parameters*/
static unsigned int storm_net_id;

/*mutext for checking per_cpu variable*/
static DEFINE_MUTEX(cpu_mutex);

/* a prototype for ip_route_input */
int ip_route_input(struct sk_buff *skb, __be32 dst, __be32 src,
				 u8 tos, struct net_device *devin);

static int pps_total_cpu_packet(struct storm_control_dev *sc_dev)
{
	int cpu=0;
	int total_packet = 0;

	/*read_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		total_packet += *per_cpu_ptr(sc_dev->pblc->pps_counter,cpu);
	}
	mutex_unlock(&cpu_mutex);
	/*read_unlock();*/

	return total_packet;
}

static unsigned int bps_total_cpu_bit(struct storm_control_dev *sc_dev)
{
	int cpu=0;
	unsigned int total_bit = 0;

	/*read_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		total_bit += *per_cpu_ptr(sc_dev->pblc->bps_counter,cpu);
	}
	mutex_unlock(&cpu_mutex);
	/*read_unlock();*/

	return total_bit;
}

static void initialize_pps_counter(struct storm_control_dev *sc_dev)
{
	int cpu=0;
		/*write_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		*per_cpu_ptr(sc_dev->pblc->pps_counter,cpu) = 0;
	}
	mutex_unlock(&cpu_mutex);
		/*write_unlock();*/
}

static void initialize_bps_counter(struct storm_control_dev *sc_dev)
{
	int cpu=0;
		/*write_lock();*/
	mutex_lock(&cpu_mutex);
	for_each_present_cpu(cpu){
		*per_cpu_ptr(sc_dev->pblc->bps_counter,cpu) = 0;
	}
	mutex_unlock(&cpu_mutex);
		/*write_unlock();*/
}

static void pps_threshold_check(struct storm_control_dev *sc_dev){
	if(sc_dev->pbl_chk.pps_checker >= sc_dev->threshold && (sc_dev->d_flag & FLAG_DOWN)){
		sc_dev->d_flag = FLAG_UP;
		sc_dev->pbl_chk.pps_checker = 0;
		initialize_pps_counter(sc_dev);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet per second was more than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "--------Blocking started at %s.--------\n",sc_dev->if_name);
	    	printk(KERN_INFO "Packet was dropped at %s.\n",sc_dev->if_name);
    	}
    else if(sc_dev->pbl_chk.pps_checker < sc_dev->threshold && (sc_dev->d_flag & FLAG_DOWN)){
	    	sc_dev->f_flag = FLAG_UP;
		sc_dev->pbl_chk.pps_checker = 0;
		initialize_pps_counter(sc_dev);
	    	printk(KERN_INFO "Packet per second was less than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "Blocking Packet ended at %s.\n",sc_dev->if_name);
    	}	
    else if(sc_dev->pbl_chk.pps_checker >= sc_dev->low_threshold && (sc_dev->d_flag & FLAG_UP)){
		sc_dev->pbl_chk.pps_checker = 0;
	    	initialize_pps_counter(sc_dev);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Packet per second was more than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "Dropping packet continues at %s.\n",sc_dev->if_name);
    	}
    else if(sc_dev->pbl_chk.pps_checker < sc_dev->low_threshold && (sc_dev->d_flag & FLAG_UP)){
	    	sc_dev->f_flag = FLAG_UP;
	    	sc_dev->d_flag = FLAG_DOWN;
		sc_dev->pbl_chk.pps_checker = 0;
		initialize_pps_counter(sc_dev);
	    	printk(KERN_INFO "Packet per second was less than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "--------Packet blocking ended at %s .--------\n",sc_dev->if_name);
    	}
}

static void bps_threshold_check(struct storm_control_dev *sc_dev){
	if(sc_dev->pbl_chk.bps_checker >= sc_dev->threshold && (sc_dev->d_flag & FLAG_DOWN)){
		sc_dev->d_flag = FLAG_UP;
		sc_dev->pbl_chk.pps_checker = 0;
		initialize_bps_counter(sc_dev);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Bit per second was more than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "--------Blocking started at %s.--------\n",sc_dev->if_name);
	    	printk(KERN_INFO "Packet was dropped at %s.\n",sc_dev->if_name);
    	}
    else if(sc_dev->pbl_chk.bps_checker < sc_dev->threshold && (sc_dev->d_flag & FLAG_DOWN)){
		sc_dev->pbl_chk.bps_checker = 0;
		initialize_bps_counter(sc_dev);
	    	printk(KERN_INFO "Bit per second was less than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "Blocking packet ended at %s.\n",sc_dev->if_name);
    	}
    else if(sc_dev->pbl_chk.bps_checker >= sc_dev->low_threshold && (sc_dev->d_flag & FLAG_UP)){
		sc_dev->pbl_chk.bps_checker = 0;
	    	initialize_bps_counter(sc_dev);
		mod_timer(&sc_timer, jiffies + TIMER_TIMEOUT_SECS*HZ);
	    	printk(KERN_INFO "Bit per second was more than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "Dropping packet continues at %s.\n",sc_dev->if_name);
    	}
    else if(sc_dev->pbl_chk.bps_checker < sc_dev->low_threshold && (sc_dev->d_flag & FLAG_UP)){
	    	sc_dev->d_flag = FLAG_DOWN;
		sc_dev->pbl_chk.bps_checker = 0;
		initialize_bps_counter(sc_dev);
	    	printk(KERN_INFO "Bit per second was less than the threthold at %s.\n",sc_dev->if_name);
	    	printk(KERN_INFO "--------Blocking packet ended at %s.--------\n",sc_dev->if_name);
    	}
}

static void check_packet(unsigned long data)
{
	struct storm_control_dev *sc_dev = (struct storm_control_dev *)data;

	printk(KERN_INFO "--------One Second passed--------\n");
	if(sc_dev->pbl_type & PPS){
		sc_dev->pbl_chk.pps_checker = pps_total_cpu_packet(sc_dev);
    		pps_threshold_check(sc_dev);
	}
	else if(sc_dev->pbl_type & BPS){
		sc_dev->pbl_chk.bps_checker = bps_total_cpu_bit(sc_dev);
    		bps_threshold_check(sc_dev);
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
		dev_put(skb->dev);
		return -1;
	}

	dev_put(skb->dev);
	return 0;
}

/*the function hooked incoming packet*/
unsigned int
storm_hook(
	void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{       
	struct storm_control_dev *sc_dev;
	struct net *net;
	if(!skb){
            return NF_ACCEPT;
        }

	/*net = get_net(&init_net);*/
	net = get_net(&init_net);
	struct storm_net *storm = net_generic(net,storm_net_id);

	list_for_each_entry_rcu(sc_dev,&storm->if_list,list){
		if(skb->dev == sc_dev->dev){
	    		/*Broadcast processing*/
	    		if(skb->pkt_type == PACKET_BROADCAST && (sc_dev->t_type & TRAFFIC_TYPE_BROADCAST)){
	    			if((sc_dev->f_flag & FLAG_UP) && (sc_dev->d_flag & FLAG_DOWN)){
					sc_dev->f_flag = FLAG_DOWN;
					printk(KERN_INFO "First broadcast packet was arrived at %s.\n",sc_dev->if_name);
					printk(KERN_INFO "One second timer started.\n");

					sc_timer.expires = jiffies + TIMER_TIMEOUT_SECS*HZ;
					sc_timer.data = (unsigned long)&sc_dev;
					sc_timer.function = check_packet;
					add_timer(&sc_timer);

					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
	    			}
				else if(sc_dev->d_flag & FLAG_DOWN){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
				}
				else if(sc_dev->d_flag & FLAG_UP){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_DROP;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_DROP;
					}
				}
			}
	    		else if(skb->pkt_type == PACKET_MULTICAST && (sc_dev->t_type & TRAFFIC_TYPE_MULTICAST)){
	    			if((sc_dev->f_flag & FLAG_UP) && (sc_dev->d_flag & FLAG_DOWN)){
					sc_dev->f_flag = FLAG_DOWN;
					printk(KERN_INFO "First multicast packet was arrived at %s.\n",sc_dev->if_name);
					printk(KERN_INFO "--------One second timer started--------\n");

					sc_timer.expires = jiffies + TIMER_TIMEOUT_SECS*HZ;
					sc_timer.data = (unsigned long)&sc_dev;
					sc_timer.function = check_packet;
					add_timer(&sc_timer);

					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
	    			}
				else if(sc_dev->d_flag & FLAG_DOWN){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
				}
				else if(sc_dev->d_flag & FLAG_UP){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_DROP;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_DROP;
					}
				}
			}
			else if((route4_input(skb) == -1) && (sc_dev->t_type & TRAFFIC_TYPE_UNKNOWN_UNICAST)){
				if((sc_dev->f_flag & FLAG_UP) && (sc_dev->d_flag & FLAG_DOWN)){
					sc_dev->f_flag = FLAG_DOWN;
					printk(KERN_INFO "First unknown_unicast packet was arrived at %s.\n",sc_dev->if_name);
					printk(KERN_INFO "--------One second timer started--------\n");

					sc_timer.expires = jiffies + TIMER_TIMEOUT_SECS*HZ;
					sc_timer.data = (unsigned long)&sc_dev;
					sc_timer.function = check_packet;
					add_timer(&sc_timer);
					
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
	    			}
				else if(sc_dev->d_flag & FLAG_DOWN){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_ACCEPT;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_ACCEPT;
					}
				}
				else if(sc_dev->d_flag & FLAG_UP){
					if(sc_dev->pbl_type & PPS){
						this_cpu_inc(*sc_dev->pblc->pps_counter);
						return NF_DROP;
					}
					else if(sc_dev->pbl_type & BPS){
						this_cpu_inc(*sc_dev->pblc->bps_counter);
						return NF_DROP;
					}
				}
			}
			else{
				return NF_ACCEPT;
			}
		}
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops_storm = {
	.hook = storm_hook,
	.hooknum = NF_INET_PRE_ROUTING,
        .pf = NFPROTO_IPV4,
    	.priority = NF_IP_PRI_FIRST
};

static struct storm_control_dev *storm_find_if(struct storm_net *storm,char *dev)
{
	struct storm_control_dev *sc_dev;

	list_for_each_entry_rcu(sc_dev,&storm->if_list,list){
		if(strncmp(sc_dev->if_name,dev,STORM_EPNAME_MAX)==0){
			return sc_dev;
		}
	}

	return NULL;
}

static int storm_add_if(struct storm_net *storm,struct storm_param *sp)
{
	bool found = false;
	struct net *net;
	struct storm_control_dev *sc_dev,*next;

	sc_dev = (struct storm_control_dev *)kmalloc(sizeof(struct storm_control_dev),
									GFP_KERNEL);
	
	if(!sc_dev){
		return -ENOMEM;
	}
	memset(sc_dev,0,sizeof(*sc_dev));
	net = get_net(&init_net);

	if (IS_ERR(net)) {
		pr_debug("%s: invalid netns\n", __func__);
		kfree(sc_dev);
		return PTR_ERR(net);
	}
	sc_dev->net = net;

	sc_dev->if_name = sp->dev;
	sc_dev->dev = dev_get_by_name(&init_net,sp->dev);
	if (!sc_dev->dev){
		return -1;
	}

	if(sp->traffic_type & TRAFFIC_TYPE_BROADCAST){
		sc_dev->t_type = TRAFFIC_TYPE_BROADCAST;
		sc_dev->f_flag = FLAG_UP;
		sc_dev->d_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is broadcast.\n");
        }
        else if(sp->traffic_type & TRAFFIC_TYPE_MULTICAST){
		sc_dev->t_type = TRAFFIC_TYPE_MULTICAST;
		sc_dev->f_flag = FLAG_UP;
		sc_dev->d_flag = FLAG_DOWN;
            	printk(KERN_INFO "Control target is multicast.\n");
        }
	else if(sp->traffic_type & TRAFFIC_TYPE_UNKNOWN_UNICAST){
		sc_dev->t_type = TRAFFIC_TYPE_UNKNOWN_UNICAST;
		sc_dev->f_flag = FLAG_UP;
		sc_dev->d_flag = FLAG_DOWN;
		printk(KERN_INFO "Control target is unknown_unicast.\n");
	}
        else{
            printk(KERN_INFO "this traffic type could not be registered.\n");
        }

	sc_dev->pbl_type = sp->control_type;

	if(sc_dev->pbl_type & PPS){
		sc_dev->pblc->pps_counter = alloc_percpu(int);
		if(sc_dev->pblc->pps_counter == NULL){
			kfree(sc_dev);
			return -1;
		}
	}
	else if(sc_dev->pbl_type & BPS || sc_dev->pbl_type & LEVEL){
		sc_dev->pblc->bps_counter = alloc_percpu(unsigned int);
		if(sc_dev->pblc->bps_counter == NULL){
			kfree(sc_dev);
			return -1;
		}
	}

	sc_dev->threshold = sp->threshold;
	if(sp->low_threshold > 0){
		sc_dev->low_threshold = sp->low_threshold;
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

	return 0;
}
static void storm_del_if(struct storm_control_dev *sc_dev)
{
	put_net(sc_dev->net);
	dev_put(sc_dev->dev);
	if(sc_dev->pbl_type & PPS){
		free_percpu(sc_dev->pblc->pps_counter);
	}
	else if(sc_dev->pbl_type & BPS || sc_dev->pbl_type & LEVEL){
		free_percpu(sc_dev->pblc->bps_counter);

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

static struct nla_policy storm_nl_policy[STORM_ATTR_MAX + 1] = {
	[STORM_ATTR_IF] = { .type = NLA_BINARY,
			.len = sizeof(struct storm_param) },
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
	struct storm_param sp;

	if (!info->attrs[STORM_ATTR]){
		return -EINVAL;
	}

	nla_memcpy(&sp,info->attrs[STORM_ATTR],sizeof(sp));

	sc_dev = storm_find_if(storm,sp.dev);
	if(sc_dev){
		return -EEXIST;
	}

	ret = storm_add_if(storm,&sp);
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
	struct storm_param sp;

	if (!info->attrs[STORM_ATTR_IF]){
		return -EINVAL;
	}

	nla_memcpy(&sp,info->attrs[STORM_ATTR_IF],sizeof(sp));
	
	sc_dev = storm_find_if(storm,sp.dev);
	if(!sc_dev){
		return -ENOENT;
	}

	storm_del_if(sc_dev);

	return 0;
}
    
static int 
__init stctl_init_module(void)
{       
        int ret = 0;

	init_timer(&sc_timer);
	/*sc_timer.expires = jiffies + TIMER_TIMEOUT_SECS*HZ;
	sc_timer.data = 0;
	sc_timer.function = check_packet;*/

	ret = register_pernet_subsys(&storm_net_ops);
	if(ret){
		goto netns_failed;
	}

	ret = nf_register_hook(&nf_ops_storm);
        if(ret){
                printk(KERN_INFO "failed to register hook.\n");
		goto register_hook_failed;
        }

	ret = genl_register_family(&storm_nl_family);
	if(ret){
		printk(KERN_INFO "failed to register genl.\n");
		goto genl_register_failed;
	}

	printk(KERN_INFO "storm_control module is loaded\n");

	return ret;

genl_register_failed:
	nf_unregister_hook(&nf_ops_storm);

register_hook_failed:
	del_timer(&sc_timer);

netns_failed:
        return ret;
}
module_init(stctl_init_module);


static void 
__exit stctl_exit_module(void)
{
	nf_unregister_hook(&nf_ops_storm);
	genl_unregister_family(&storm_nl_family);
	unregister_pernet_subsys(&storm_net_ops);
	del_timer(&sc_timer);
    	printk(KERN_INFO "Storm control module was Removed.\n");
}
module_exit(stctl_exit_module);
