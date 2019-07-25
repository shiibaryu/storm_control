
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/times.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <asm/unaligned.h>
#include <linux/if_vlan.h>
#include <net/switchdev.h>
#include <trace/events/bridge.h>
#include <linux/rhashtable.h>

#include "storm_fdb.h"

static const struct rhashtable_params br_fdb_rht_params = {
	.head_offset = offsetof(struct net_bridge_fdb_entry, rhnode),
	.key_offset = offsetof(struct net_bridge_fdb_entry, key),
	.key_len = sizeof(struct net_bridge_fdb_key),
	.automatic_shrinking = true,
	.locks_mul = 1,
};

static struct net_bridge_fdb_entry *fdb_find_rcu(struct rhashtable *tbl,
						 const unsigned char *addr,
						 __u16 vid)
{
	struct net_bridge_fdb_key key;

	WARN_ON_ONCE(!rcu_read_lock_held());

	key.vlan_id = vid;
	memcpy(key.addr.addr, addr, sizeof(key.addr.addr));

	return rhashtable_lookup(tbl, &key, br_fdb_rht_params);
}

static struct net_bridge_fdb_entry *br_fdb_find(struct net_bridge *br,
						const unsigned char *addr,
						__u16 vid)
{
	struct net_bridge_fdb_entry *fdb;

	lockdep_assert_held_once(&br->hash_lock);

	rcu_read_lock();
	fdb = fdb_find_rcu(&br->fdb_hash_tbl, addr, vid);
	rcu_read_unlock();

	return fdb;
}

struct net_bridge_fdb_entry *br_fdb_find_rcu(struct net_bridge *br,
					     const unsigned char *addr,
					     __u16 vid)
{
	return fdb_find_rcu(&br->fdb_hash_tbl, addr, vid);
}

