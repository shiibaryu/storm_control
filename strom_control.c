#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>

MODULE_LICENSE("Dual BSD/GPL"):
MODULE_AUTHOR("siiba");
MODULE_INFO("strom control module");
MODULE_DESCRIPTION("This is a linux module of strom control.");

int flag = 0;
static char *d_name;
module_param(d_name,char,0660);
static int *threshold;
module_param(threshold,int,0660);

/*
    ストーム制御概要
    1. デバイスをユーザー空間から指定
    2. そのデバイスから入るパケットを計測
    3. 閾値を設けておき、その閾値を超えるBUMが指定したデバイスから
       入ってきていたらそのデバイスを一旦閉じる
    4. 一定時間経ったら開ける
    5. 2~4の繰り返し
*/

int mesure_netdev(struct net_device *ndev,){

    return ;
}

int get_netdev_mesurement_result()
{
        struct net_device *dev;
        int bum_flow;

        read_lock(&dev_base_lock);
        for_each_netdev(&init_net,dev){
                if(strcmp(d_name,dev->name)==0){
                    bum_flow = mesure_netdev(dev);
                }
        }
        read_unlock(&dev_base_lock);
        return bum_flow;
}

int check_flow(int result){
        if(result >= threshold){
            dev_close(d_name);
            flag = 1;
        }
        else{
            if(flag = 1){
                dev_open(d_name);
                flag = 0;
            }
        }
        return 0;
}


static int module_init(void)
{   
        int mesure_result;
        int bum_flow;

        while(loop){
            bum_flow = get_netdev_mesure_result();
            check_flow(bum_flow);
        }
        
        return 0;
}

static void module_exit(void){
        printk(KERN_INFO "See you!");
}

module_init(module_init);
module_exit(module_exit);
