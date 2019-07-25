#ifndef _BR_PRIVATE_H
#define _BR_PRIVATE_H

#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

struct bridge_id {
	unsigned char	prio[2];
	unsigned char	addr[ETH_ALEN];
};

struct mac_addr {
	unsigned char	addr[ETH_ALEN];
};

struct net_bridge_vlan {
	struct rhash_head		vnode;
	struct rhash_head		tnode;
	u16				vid;
	u16				flags;
	u16				priv_flags;
	struct br_vlan_stats __percpu	*stats;
	union {
		struct net_bridge	*br;
		struct net_bridge_port	*port;
	};
	union {
		refcount_t		refcnt;
		struct net_bridge_vlan	*brvlan;
	};

	struct br_tunnel_info		tinfo;

	struct list_head		vlist;

	struct rcu_head			rcu;
};

struct net_bridge_vlan_group {
	struct rhashtable		vlan_hash;
	struct rhashtable		tunnel_hash;
	struct list_head		vlan_list;
	u16				num_vlans;
	u16				pvid;
};

struct net_bridge_port {
	struct net_bridge		*br;
	struct net_device		*dev;
	struct list_head		list;

	unsigned long			flags;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	struct net_bridge_vlan_group	__rcu *vlgrp;
#endif
	struct net_bridge_port		__rcu *backup_port;

	/* STP */
	u8				priority;
	u8				state;
	u16				port_no;
	unsigned char			topology_change_ack;
	unsigned char			config_pending;
	port_id				port_id;
	port_id				designated_port;
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	u32				path_cost;
	u32				designated_cost;
	unsigned long			designated_age;

	struct timer_list		forward_delay_timer;
	struct timer_list		hold_timer;
	struct timer_list		message_age_timer;
	struct kobject			kobj;
	struct rcu_head			rcu;

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	struct bridge_mcast_own_query	ip4_own_query;
#if IS_ENABLED(CONFIG_IPV6)
	struct bridge_mcast_own_query	ip6_own_query;
#endif /* IS_ENABLED(CONFIG_IPV6) */
	unsigned char			multicast_router;
	struct bridge_mcast_stats	__percpu *mcast_stats;
	struct timer_list		multicast_router_timer;
	struct hlist_head		mglist;
	struct hlist_node		rlist;
#endif

#ifdef CONFIG_SYSFS
	char				sysfs_name[IFNAMSIZ];
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
	struct netpoll			*np;
#endif
#ifdef CONFIG_NET_SWITCHDEV
	int				offload_fwd_mark;
#endif
	u16				group_fwd_mask;
	u16				backup_redirected_cnt;
};

struct net_bridge_fdb_key {
	mac_addr addr;
	u16 vlan_id;
};

struct net_bridge_fdb_entry {
	struct rhash_head		rhnode;
	struct net_bridge_port		*dst;

	struct net_bridge_fdb_key	key;
	struct hlist_node		fdb_node;
	unsigned char			is_local:1,
					is_static:1,
					is_sticky:1,
					added_by_user:1,
					added_by_external_learn:1,
					offloaded:1;

	/* write-heavy members should not affect lookups */
	unsigned long			updated ____cacheline_aligned_in_smp;
	unsigned long			used;

	struct rcu_head			rcu;
};
static struct net_bridge_fdb_entry *fdb_find_rcu(struct rhashtable *tbl,
						 const unsigned char *addr,
						 __u16 vid);

static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br,
						const unsigned char *addr,
						__u16 vid);

struct net_bridge_fdb_entry *br_fdb_find_rcu(struct net_bridge *br,
					     const unsigned char *addr,
					     __u16 vid);                        