#include <linux/security.h>


#define VER_LEN  4
#define DATA_LEN 1024
struct __ctl_cmd_base
{
    char ver[VER_LEN];
    int cmd;
    int result;
};

struct __ctl_cmd
{
    struct __ctl_cmd_base base;
    char data[DATA_LEN];
	int len;
};

#define PATH_DEPTH 6
  
#define DEBUG_ENABLE     1
#if (DEBUG_ENABLE > 0)
#define LOGD(fmt, args...) printk(KERN_DEBUG "[MyLSM] DEBUG:"fmt, ##args)
#define LOGI(fmt, args...) printk(KERN_INFO "[MyLSM] INFO:"fmt, ##args)
#define LOGW(fmt, args...) printk(KERN_WARNING "[MyLSM] WARNING:"fmt, ##args)
#define LOGE(fmt, args...) printk(KERN_ERR "[MyLSM] ERR:"fmt, ##args)
#else
#define LOGD(...) do{}while(0)
#define LOGI(...) do{}while(0)
#define LOGW(...) do{}while(0)  
#define LOGE(...) do{}while(0)
#endif




