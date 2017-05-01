#include "caphook.h"
#include <linux/netlink.h>
#include <net/netlink.h>
#include <linux/spinlock.h>


#define VER_OF_CTL(ctl) ((ctl)->ver)
#define CMD_OF_CTL(ctl) ((ctl)->cmd)
#define RESULT_OF_CTL(ctl) ((ctl)->result)
#define DATA_OF_CTL(ctl) ((ctl)->data)

extern struct net init_net;

enum {
    CMD_ENABLE_LSM = 0,
    CMD_DISENABLE_LSM,
    CMD_SET_PID,
    CMD_SET_FILE,
    CMD_GET_FILE,
};

enum
{
    ENTRY_RM = 0,
    ENTRY_RMDIR,
    ENTRY_RENAME,
    ENTRY_CHMOD,
    ENTRY_CHOWN,
};

static char *version = "V1.0";
static int enabled = 0;
static struct sock *socknl;
static pid_t user_pid; 
static spinlock_t lock;

#define MAX_FN_SIZE 5
typedef int (* pfn)(void *, int);
pfn msg_handle[MAX_FN_SIZE];

#define MAX_PID_NUM   4
#define MAX_FILE_NUM  4
#define FILE_NAME_LEN 128
static int resource_pid[MAX_PID_NUM];
static char resource_file[MAX_FILE_NUM][FILE_NAME_LEN];
static int pid_num = 0;
static int file_num = 0;

static char *entry_ops[] = {"rm", "rmdir", "rename", "chmod", "chown"};

/******************************************************************************/

static int my_task_kill(struct task_struct *p, struct siginfo *info, int sig, u32 secid)
{
    if (enabled == 0) {
        return 0;
    }
    if (pid_num > 0) {
	int i;
        for (i = 0; i < MAX_PID_NUM; i++) {
            if (resource_pid[i] == p->pid) {
                LOGW("not allowed to kill the protected process:%s\n", p->comm);
                return -1;
            }
        }
    }
    return 0;
}

#ifdef CONFIG_SECURITY_PATH
static int str_lookup(char *str, char *array[], int slen, int depth)
{
    int i;
    int len;
    int ilen;
    for (i = 0; i < depth; i++) {
        ilen = strlen(array[i]);
        if (slen > ilen) {
            len = ilen;        
        } else {
            len = slen;
        }
        if (strncmp(str, array[i], len) == 0) {
            return 0;
        }
    }
    return -1;    
}

static int path_lookup(char *dest, char *source[], int depth)
{
    int i;
    int sep = 0;
    for (i = 0; i < FILE_NAME_LEN; i++) {
        if (dest[i] == '/') {
            sep = 1;
            if (str_lookup(&dest[i + 1], source, (FILE_NAME_LEN - i - 1), depth) != 0) {
                return -1;
            }
        }    
    }
    if (sep == 0) {
        if (str_lookup(dest, source, FILE_NAME_LEN, depth) != 0) {
            return -1;
        }
    }
    return 0;
}

static int entry_check(struct dentry *dentry, int type)
{
    int i = 0;
    int depth = 0;
    char *entry[PATH_DEPTH];
    struct dentry *dn = dentry;
    struct dentry *pdn = 0;

    if (file_num > 0) {
        // not possible 
        if (dentry == 0) {
            return 0;
        }
        for (i = 0; i < PATH_DEPTH; i++) {
	    entry[i] = 0;
        }

        i = 0;
        entry[0] = dentry->d_iname;
        while (true) {
	    i++;	
            pdn = dn->d_parent;
            if (pdn == 0) {
		break;
            }
	    if (i >= PATH_DEPTH) {
	        break;
            }
            entry[i] = pdn->d_iname;               
	    dn = pdn;      
        }

        depth = i;
        for (i = 0; i < MAX_FILE_NUM; i++) {
            if (resource_file[i][0] != 0) {
                if (path_lookup(resource_file[i], entry, depth) == 0) {
                      LOGW("not allowed to %s file:%s\n", entry_ops[type], resource_file[i]);
                      return -1;
                }
            }
        }    
    }  
    
    return 0;
}

static int my_path_unlink(struct path *dir, struct dentry *dentry)
{
    if (enabled == 0) {
        return 0;
    }
    return entry_check(dentry, ENTRY_RM);
}

static int my_path_rmdir(struct path *dir, struct dentry *dentry)
{
    if (enabled == 0) {
        return 0;
    }
    return entry_check(dentry, ENTRY_RMDIR);
}

static int my_path_rename(struct path *old_path, struct dentry *old_dentry,
			     struct path *new_path, struct dentry *new_dentry)
{
    if (enabled == 0) {
        return 0;
    }
    return entry_check(old_dentry, ENTRY_RENAME);
}

static int my_path_chmod(struct dentry *dentry, struct vfsmount *mnt,
			    mode_t mode)
{
    if (enabled == 0) {
        return 0;
    }
    return entry_check(dentry, ENTRY_CHMOD);
}

static int my_path_chown(struct path *path, uid_t uid, gid_t gid)
{
    if (enabled == 0) {
        return 0;
    }
    return entry_check(path->dentry, ENTRY_CHOWN);
}

#endif


static struct security_operations my_security_ops = {
    .name                = "my_lsm",
#ifdef CONFIG_SECURITY_PATH
    .path_unlink         = my_path_unlink,
    .path_rmdir          = my_path_rmdir,
    .path_chmod          = my_path_chmod,
    .path_chown          = my_path_chown,
    .path_rename         = my_path_rename,
#endif
    .task_kill           = my_task_kill,
};

void resource_init(void)
{
    int i;
    for (i = 0; i < MAX_PID_NUM; i++) {
        resource_pid[i] = -1;
    }
    memset(resource_file, 0, sizeof(resource_file));
    pid_num = 0;
    file_num = 0;
}


static void set_cmd_ver(struct __ctl_cmd_base *ctl_base)
{
    char *ver = VER_OF_CTL(ctl_base);
    strncpy(ver, version, VER_LEN);
}

static int mylsm_enable(void *buffer, int seq)
{    
    enabled = 1;
    return 0;
}

static int mylsm_disenable(void *buffer, int seq)
{
    enabled = 0;
    resource_init();
    return 0;
}

static int mylsm_set_pid(void *buffer, int seq) {
    if (enabled == 0) {
	return 0;
    }
    if (pid_num >= MAX_PID_NUM) {
	return 0;
    }
    struct __ctl_cmd *ctl = (struct __ctl_cmd *)buffer;
    char *data = DATA_OF_CTL(ctl);
    int pid = *(int *)data;

    int i;
	for (i = 0; i < MAX_PID_NUM; i++) {
        if (resource_pid[i] == -1) {
            resource_pid[i] = pid;
            pid_num++;
            break;
        }
    }
}

static int mylsm_set_file(void *buffer, int seq) {
    if (enabled == 0) {
	return 0;
    }
    if (file_num >= MAX_FILE_NUM) {
        return 0;
    }
    struct __ctl_cmd *ctl = (struct __ctl_cmd *)buffer;
    char *data = DATA_OF_CTL(ctl);
    int len = strlen(data);
    if (len >= FILE_NAME_LEN) {
	return 0;
    }

    int i;
    for (i = 0; i < MAX_FILE_NUM; i++) {
        if (resource_file[i][0] == 0) {
            strcpy(resource_file[i], data);
            file_num++;
            break;
        }
    }
}

static int mylsm_get_file(void *buffer, int seq) {
    if (enabled == 0) {
	return;
    }
    int payload = NLMSG_SPACE(sizeof(struct __ctl_cmd));
    struct sk_buff *skb_nltmp = alloc_skb(NLMSG_SPACE(payload), GFP_ATOMIC);
    if (skb_nltmp == 0) {
        LOGE("alloc socket buffer failed. len:%d", payload);
        return -1;
    }
    struct nlmsghdr *nlh = nlmsg_put(skb_nltmp, user_pid, (seq + 1), 0, NLMSG_SPACE(payload) - sizeof(struct nlmsghdr), 0);
    if (nlh == 0) {
        LOGE("too big payload!");
        return -1;        
    }
    char *data = NLMSG_DATA(nlh);
    struct __ctl_cmd_base *ctl_base = (struct __ctl_cmd_base *)data;
    set_cmd_ver(ctl_base);
    CMD_OF_CTL(ctl_base) = CMD_GET_FILE;
    struct __ctl_cmd *ctl = (struct __ctl_cmd *)data;
    DATA_OF_CTL(ctl)[0] = 0;
    ctl->len = 0;
    if (file_num > 0) {
	int i;
        int len;
	int total = 0;
	data = DATA_OF_CTL(ctl);
	for (i = 0; i < MAX_FILE_NUM; i++) {
            if (resource_file[i][0] != 0) {
                len = strlen(resource_file[i]);
                strcpy(data, resource_file[i]);
                data[len] = 0;
                data = &data[len + 1];
		total += (len + 1);
            }               
        }
	ctl->len = total;
    }
    RESULT_OF_CTL(ctl_base) = 0;

    int result = netlink_unicast(socknl, skb_nltmp, user_pid, MSG_DONTWAIT);
    if (result < 0) {
        LOGE("unicast send error=%d\n", result);
        return -1;
    }    
    return 0;
}

static void pfn_init(void)
{
    msg_handle[0] = mylsm_enable;
    msg_handle[1] = mylsm_disenable;
    msg_handle[2] = mylsm_set_pid;
    msg_handle[3] = mylsm_set_file;    
    msg_handle[4] = mylsm_get_file;
}

static int input_check(struct __ctl_cmd_base *ctl_base)
{
    char *ver = VER_OF_CTL(ctl_base);
    int cmd = CMD_OF_CTL(ctl_base);
    if (strncmp(ver, version, sizeof(version)) != 0) {
        return -1;
    }
    if ((cmd < 0) || (cmd >= MAX_FN_SIZE)) {
        return -1;
    }
    return 0;
}

static void msg_input(struct sk_buff *skb)
{
    int len;
    int seq;
    unsigned long flag;
    struct nlmsghdr *nlh;
    struct __ctl_cmd_base *ctl_base;

    if (skb == 0) {
        LOGE("input msg is null.\n");
        return;
    }
	
    spin_lock_irqsave(&lock, flag);
    len = skb->len;
    nlh = nlmsg_hdr(skb);
    seq = nlh->nlmsg_seq;
    if(NLMSG_OK(nlh, len)) {        
        user_pid = nlh->nlmsg_pid; 
        ctl_base = (struct __ctl_cmd_base *)NLMSG_DATA(nlh);
        if (input_check(ctl_base) < 0) {
            goto out;
        }      
        msg_handle[CMD_OF_CTL(ctl_base)]((void *)ctl_base, seq);        
    } else {
        LOGE("input msg length invalid. skb len:%d, nlmsg_len:%d, sizeof(struct nlmsghdr):%d\n", 
                 len, nlh->nlmsg_len, sizeof(struct nlmsghdr));
    }

out:
    spin_unlock_irqrestore(&lock, flag);
}


// SECOND INITIALIZED.
int netlink_init(void)
{
    resource_init();
    pfn_init();

    socknl = netlink_kernel_create(&init_net, NETLINK_MYLSM, 0, msg_input, NULL, THIS_MODULE);
    if (socknl == 0) {
        LOGE("create kernel netlink error.\n");
        return -1;
    }
    return 0;
}
__initcall(netlink_init);


// FIRST INITIALIZED.
int __init my_security_init(void) 
{
    if (!security_module_enable(&my_security_ops)) {
	LOGE("my security module enable failed.\n");
        return 0;
    }

    /* register ourselves with the security framework */
    if (register_security(&my_security_ops)) {
	LOGE("register my security machenism failed.\n");
        return 0;
    }
        
    spin_lock_init(&lock);    
    enabled = 0;
    return 0;
}

security_initcall(my_security_init);





