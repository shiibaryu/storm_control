
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

#define BR_HASH_BITS 8
#define BR_HASH_SIZE (1 << BR_HASH_BITS)

#define BR_HOLD_TIME (1*HZ)

#define BR_PORT_BITS	10
#define BR_MAX_PORTS	(1<<BR_PORT_BITS)

#define BR_MULTICAST_DEFAULT_HASH_MAX 4096

#define BR_VERSION	"2.3"

/* Control of forwarding link local multicast */
#define BR_GROUPFWD_DEFAULT	0
/* Don't allow forwarding of control protocols like STP, MAC PAUSE and LACP */
enum {
	BR_GROUPFWD_STP		= BIT(0),
	BR_GROUPFWD_MACPAUSE	= BIT(1),
	BR_GROUPFWD_LACP	= BIT(2),
};

#define BR_GROUPFWD_RESTRICTED (BR_GROUPFWD_STP | BR_GROUPFWD_MACPAUSE | \
				BR_GROUPFWD_LACP)
/* The Nearest Customer Bridge Group Address, 01-80-C2-00-00-[00,0B,0C,0D,0F] */
#define BR_GROUPFWD_8021AD	0xB801u

/* Path to usermode spanning tree program */
#define BR_STP_PROG	"/sbin/bridge-stp"

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

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
/* our own querier */
struct bridge_mcast_own_query {
	struct timer_list	timer;
	u32			startup_sent;
};

/* other querier */
struct bridge_mcast_other_query {
	struct timer_list		timer;
	unsigned long			delay_time;
};

/* selected querier */
struct bridge_mcast_querier {
	struct br_ip addr;
	struct net_bridge_port __rcu	*port;
};

/* IGMP/MLD statistics */
struct bridge_mcast_stats {
	struct br_mcast_stats mstats;
	struct u64_stats_sync syncp;
};
#endif

struct br_vlan_stats {
	u64 rx_bytes;
	u64 rx_packets;
	u64 tx_bytes;
	u64 tx_packets;
	struct u64_stats_sync syncp;
};

struct br_tunnel_info {
	__be64			tunnel_id;
	struct metadata_dst	*tunnel_dst;
};

/* private vlan flags */
enum {
	BR_VLFLAG_PER_PORT_STATS = BIT(0),
	BR_VLFLAG_ADDED_BY_SWITCHDEV = BIT(1),
};

/**
 * struct net_bridge_vlan - per-vlan entry
 *
 * @vnode: rhashtable member
 * @vid: VLAN id
 * @flags: bridge vlan flags
 * @priv_flags: private (in-kernel) bridge vlan flags
 * @stats: per-cpu VLAN statistics
 * @br: if MASTER flag set, this points to a bridge struct
 * @port: if MASTER flag unset, this points to a port struct
 * @refcnt: if MASTER flag set, this is bumped for each port referencing it
 * @brvlan: if MASTER flag unset, this points to the global per-VLAN context
 *          for this VLAN entry
 * @vlist: sorted list of VLAN entries
 * @rcu: used for entry destruction
 *
 * This structure is shared between the global per-VLAN entries contained in
 * the bridge rhashtable and the local per-port per-VLAN entries contained in
 * the port's rhashtable. The union entries should be interpreted depending on
 * the entry flags that are set.
 */
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

/**
 * struct net_bridge_vlan_group
 *
 * @vlan_hash: VLAN entry rhashtable
 * @vlan_list: sorted VLAN entry list
 * @num_vlans: number of total VLAN entries
 * @pvid: PVID VLAN id
 *
 * IMPORTANT: Be careful when checking if there're VLAN entries using list
 *            primitives because the bridge can have entries in its list which
 *            are just for global context but not for filtering, i.e. they have
 *            the master flag set but not the brentry flag. If you have to check
 *            if there're "real" entries in the bridge please test @num_vlans
 */
struct net_bridge_vlan_group {
	struct rhashtable		vlan_hash;
	struct rhashtable		tunnel_hash;
	struct list_head		vlan_list;
	u16				num_vlans;
	u16				pvid;
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

#define MDB_PG_FLAGS_PERMANENT	BIT(0)
#define MDB_PG_FLAGS_OFFLOAD	BIT(1)

struct net_bridge_port_group {
	struct net_bridge_port		*port;
	struct net_bridge_port_group __rcu *next;
	struct hlist_node		mglist;
	struct rcu_head			rcu;
	struct timer_list		timer;
	struct br_ip			addr;
	unsigned char			flags;
	unsigned char			eth_addr[ETH_ALEN];
};

struct net_bridge_mdb_entry {
	struct rhash_head		rhnode;
	struct net_bridge		*br;
	struct net_bridge_port_group __rcu *ports;
	struct rcu_head			rcu;
	struct timer_list		timer;
	struct br_ip			addr;
	bool				host_joined;
	struct hlist_node		mdb_node;
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

struct net_bridge {
	spinlock_t			lock;
	spinlock_t			hash_lock;
	struct list_head		port_list;
	struct net_device		*dev;
	struct pcpu_sw_netstats		__percpu *stats;
	unsigned long			options;
	/* These fields are accessed on each packet */
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	__be16				vlan_proto;
	u16				default_pvid;
	struct net_bridge_vlan_group	__rcu *vlgrp;
#endif

	struct rhashtable		fdb_hash_tbl;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	union {
		struct rtable		fake_rtable;
		struct rt6_info		fake_rt6_info;
	};
#endif
	u16				group_fwd_mask;
	u16				group_fwd_mask_required;

	/* STP */
	bridge_id			designated_root;
	bridge_id			bridge_id;
	unsigned char			topology_change;
	unsigned char			topology_change_detected;
	u16				root_port;
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	unsigned long			ageing_time;
	unsigned long			bridge_max_age;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;
	unsigned long			bridge_ageing_time;
	u32				root_path_cost;

	u8				group_addr[ETH_ALEN];

	enum {
		BR_NO_STP, 		/* no spanning tree */
		BR_KERNEL_STP,		/* old STP in kernel */
		BR_USER_STP,		/* new RSTP in userspace */
	} stp_enabled;

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING

	u32				hash_max;

	u32				multicast_last_member_count;
	u32				multicast_startup_query_count;

	u8				multicast_igmp_version;
	u8				multicast_router;
#if IS_ENABLED(CONFIG_IPV6)
	u8				multicast_mld_version;
#endif
	spinlock_t			multicast_lock;
	unsigned long			multicast_last_member_interval;
	unsigned long			multicast_membership_interval;
	unsigned long			multicast_querier_interval;
	unsigned long			multicast_query_interval;
	unsigned long			multicast_query_response_interval;
	unsigned long			multicast_startup_query_interval;

	struct rhashtable		mdb_hash_tbl;

	struct hlist_head		mdb_list;
	struct hlist_head		router_list;

	struct timer_list		multicast_router_timer;
	struct bridge_mcast_other_query	ip4_other_query;
	struct bridge_mcast_own_query	ip4_own_query;
	struct bridge_mcast_querier	ip4_querier;
	struct bridge_mcast_stats	__percpu *mcast_stats;
#if IS_ENABLED(CONFIG_IPV6)
	struct bridge_mcast_other_query	ip6_other_query;
	struct bridge_mcast_own_query	ip6_own_query;
	struct bridge_mcast_querier	ip6_querier;
#endif /* IS_ENABLED(CONFIG_IPV6) */
#endif

	struct timer_list		hello_timer;
	struct timer_list		tcn_timer;
	struct timer_list		topology_change_timer;
	struct delayed_work		gc_work;
	struct kobject			*ifobj;
	u32				auto_cnt;

#ifdef CONFIG_NET_SWITCHDEV
	int offload_fwd_mark;
#endif
	struct hlist_head		fdb_list;
};

struct br_input_skb_cb {
	struct net_device *brdev;

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	int igmp;
	int mrouters_only;
#endif

	bool proxyarp_replied;
	bool src_port_isolated;

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	bool vlan_filtered;
#endif

#ifdef CONFIG_NET_SWITCHDEV
	int offload_fwd_mark;
#endif
};


struct net_bridge_fdb_entry *fdb_find_rcu(struct rhashtable *tbl,
						 const unsigned char *addr,
						 __u16 vid);

struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br,
						const unsigned char *addr,
						__u16 vid);

struct net_bridge_fdb_entry *br_fdb_find_rcu(struct net_bridge *br,
					     const unsigned char *addr,
					     __u16 vid);                        