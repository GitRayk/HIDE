#include <linux/module.h>
#include <linux/kernel.h>

#include "output.h"
#include "input.h"
#include "kern_aes.h"
#include "kern_hash.h"
#include "kern_ioctl.h"
#include "channel.h"


static int __init my_module_init(void) {
    // 设置Netfilter钩子函数
    input_init();
    output_init();
    aes_init();
    kern_hash_init();
    ioctl_init();
    channel_init();

    pr_info("Extended module loaded\n");
    return 0;
}
 
static void __exit my_module_exit(void) {
    // 注销Netfilter钩子函数
    input_exit();
    output_exit();
    aes_exit();
    kern_hash_exit();
    ioctl_exit();
    channel_exit();

    pr_info("Extended module unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);
MODULE_LICENSE("GPL");
