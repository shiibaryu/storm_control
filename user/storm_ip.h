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

#define STORM_GENL_NAME	"storm_control"
#define STORM_GENL_VERSION	0x00

/* genl commands */
enum {
	STORM_CMD_ADD,
	__STORM_CMD_MAX,
};
#define STORM_CMD_MAX	(__STORM_CMD_MAX - 1)

#define CMD_SIZE 		6
#define traffic_name_max 	15

/*genl attrs*/
struct storm_param{
	char *dev;
	unsigned short traffic_type;
	unsigned short control_type;
	int  threshold;
	int  low_threshold;
}__attribute__((__packed__));


enum {
	STORM_ATTR_NONE,
	STORM_ATTR,	
	__STORM_ATTR_MAX,
};
#define STORM_ATTR_MAX	(__STORM_ATTR_MAX - 1)

#endif
