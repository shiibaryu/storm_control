/* storm.h */

#ifndef _STORM_H_
#define _STORM_H_

#include <linux/netlink.h>

#define STORM_VERSION "0.0.1"

#ifndef __KERNEL__
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#endif

#define AF_GRAFT_GENL_NAME	"storm_ctl"
#define AF_GRAFT_GENL_VERSION	0x00

/* genl commands */
enum {
	STORM_CMD_ADD_ENDPOINT,
	__AF_GRAFT_CMD_MAX,
};
#define STORM_CMD_MAX	(__STORM_CMD_MAX - 1)

/*genl attrs*/
struct storm_param{
	char dev[device_name_max];
	u16  traffic_type[traffic_name_max];
	char control_type[6];
	int  threshold;
	int  low_threshold;
}__attribute__((__packed__));

static struct nla_policy storm_nl_policy[STORM_ATTR_MAX + 1] = {
	[STORM_ATTR_ENDPOINT] = { .type = NLA_BINARY,
				     .len = sizeof(struct storm_param) },
};

enum {
	STORM_ATTR_NONE,
	STORM_ATTR_ENDPOINT,	/* struct graft_genl_endpoint */
	__STORM_ATTR_MAX,
};
#define STORM_ATTR_MAX	(__STORM_ATTR_MAX - 1)

#endif