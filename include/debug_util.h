#ifndef __DEBUG_H__

#define __DEBUG_H__

#define DEBUG_ENABLE 1
#if DEBUG_ENABLE
#define DEBUG_PRINT(fmt, args...) printk(fmt, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

#endif