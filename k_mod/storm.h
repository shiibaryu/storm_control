/* storm.h */

#ifndef _STORM_H_
#define _STORM_H_

#include <linux/netlink.h>
#include <linux/if.h>		

#define STORM_VERSION "0.0.1"
#define STORM_DEVNAME_MAX	IFNAMSIZ

#ifndef __KERNEL__
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#endif

#define STORM_GENL_NAME	"storm_control"
#define STORM_GENL_VERSION	0x00

/* genl commands */
enum {
	STORM_CMD_ADD_IF,
	STORM_CMD_DEL_IF,
	__STORM_CMD_MAX,
};
#define STORM_CMD_MAX	(__STORM_CMD_MAX - 1)

/*genl attrs*/
struct storm_info{
	char if_name[STORM_DEVNAME_MAX];
	int threshold;
	int low_threshold;
	unsigned short pb_type; /*flag to specify pps , bps or level*/
	unsigned short traffic_type; /* user specified traffic type*/
    unsigned short drop_flag; /*drop_flag*/
	unsigned short first_flag; /*first time or not*/
}__attribute__((__packed__));


enum {
	STORM_ATTR_NONE,
	STORM_ATTR_IF,	

	__STORM_ATTR_MAX,
};
#define STORM_ATTR_MAX	(__STORM_ATTR_MAX - 1)

#endif