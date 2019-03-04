#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>

MODULE_LICENSE("Dual BSD/GPL"):
MODULE_AUTHOR("siiba");
MODULE_INFO("stream control module");
MODULE_DESCRIPTION("This is a stream control module for network");

struct net_device *dev;

static char dev_name;
module_param(dev_name,char,0660);

static int __init init(void)
{
    struct net_device *dev;

    printk(KERN_INFO "Hello. My name is hwaddr.");

    read_lock(&dev_base_lock);
    for_each_netdev(&init_net,dev){
        if(devname==dev->name){
            printk("Dev name is %s\n",dev->name);
        }
    }
    read_unlock(&dev_base_lock);
    return 0;
}

static void module_exit(void){
    printk(KERN_INFO "See you!");
}

module_init(module_init);
module_exit(module_exit);
