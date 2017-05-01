#include <stdio.h>
#include <stdlib.h>
#include <stddef.h> // offsetof
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <linux/socket.h> // struct ucred
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/un.h> // struct sockaddr_un


#define CONSOLE_PRINT 1
#define LOGCAT_PRINT  0

#if (LOGCAT_PRINT > 0)
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, TAG,__VA_ARGS__) 
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG,__VA_ARGS__) 
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__) 
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG,__VA_ARGS__) 
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG,__VA_ARGS__)
#elif (CONSOLE_PRINT > 0)
#define LOGV(...) printf(__VA_ARGS__) 
#define LOGD(...) printf(__VA_ARGS__)  
#define LOGI(...) printf(__VA_ARGS__)  
#define LOGW(...) printf(__VA_ARGS__)  
#define LOGE(...) printf(__VA_ARGS__) 
#else
#define LOGV(...) do{}while(0)
#define LOGD(...) do{}while(0)
#define LOGI(...) do{}while(0)
#define LOGW(...) do{}while(0)  
#define LOGE(...) do{}while(0)
#endif 


#define VER_LEN  4
#define DATA_LEN 1024

#define VER_OF_CTL(ctl) ((ctl)->ver)
#define CMD_OF_CTL(ctl) ((ctl)->cmd)
#define RESULT_OF_CTL(ctl) ((ctl)->result)
#define DATA_OF_CTL(ctl) ((ctl)->data)

enum {
    CMD_ENABLE_LSM = 0,
    CMD_DISENABLE_LSM,
    CMD_SET_PID,
    CMD_SET_FILE,
    CMD_GET_FILE,
    CMD_EXIT = 99,
};

enum {
    ERR_INVALID_CMD = -1,
    ERR_NETLINK_INIT = -2,
    ERR_NETLINK_SEND = -3,
    ERR_NETLINK_RECV = -4,
    ERR_NETLINK_RSP = -5,
};

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


static char *version = "V1.0";
static char *LOCAL_SOCKET_NAME = "/data/local/tmp/lsm";

static struct msghdr msg;
static struct iovec iov;
static struct sockaddr_nl socket_dest;
static struct sockaddr_nl socket_src;
static pid_t my_pid;

static void set_cmd_ver(struct __ctl_cmd_base *ctl_base)
{
    char *ver = VER_OF_CTL(ctl_base);
    strncpy(ver, version, VER_LEN);
}

static int get_rand(void)
{
    srand((int)time(0));
    return (rand() % 32767);
}

static int check_rsp(int cmd, struct nlmsghdr *nlh, int seq)
{
    if (nlh->nlmsg_pid != my_pid) { 
        return -1;
    }
    if (nlh->nlmsg_seq != (seq + 1)) {
        return -1;
    }

    struct __ctl_cmd_base *ctl_base = NLMSG_DATA(nlh);
    char *ver = VER_OF_CTL(ctl_base);
    if (strncmp(ver, version, VER_LEN) != 0) {
        return -1;
    }
    if (CMD_OF_CTL(ctl_base) != cmd) {
        return -1;
    }
    if (RESULT_OF_CTL(ctl_base) != 0) {
        return -1;
    }
    return 0;    
}

static struct nlmsghdr *init_nlh(void)
{
    int payload = sizeof(struct __ctl_cmd);
    int len = NLMSG_SPACE(payload);
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(len);
    if (nlh == 0) {
        LOGE("malloc error:%s, len:%d\n", strerror(errno), len);
	return 0;
    }
    return nlh;    
}

static int init_netlink(void)
{  
    int fd;
    if ((fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_MYLSM)) < 0) {
        LOGE("create socket. error:%s\n", strerror(errno));
        return -1;
    }

    memset(&socket_src, 0, sizeof(struct sockaddr_nl));
    socket_src.nl_family = PF_NETLINK;
    socket_src.nl_pid = my_pid;
    if (bind(fd, (struct sockaddr *)&socket_src, sizeof(struct sockaddr_nl)) < 0) {
        LOGE("bind socket. error:%s\n", strerror(errno));
        return -1;
    }

    memset(&socket_dest, 0, sizeof(struct sockaddr_nl));
    socket_dest.nl_family = PF_NETLINK;

    memset(&msg, 0, sizeof(struct msghdr));   
    msg.msg_name = &socket_dest;
    msg.msg_namelen = sizeof(struct sockaddr_nl);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return fd;
}

static void show_usage(void)
{
    LOGW("Unix socket of this proxy process receive string formatted command.\n \
	    the first char of the string is command type, and followed by the parameter if necessary.\n \
	    e exit the proxy proxess\n \
	    O enable my LSM in kernel\n \
	    o disable my LSM in kernel\n \
	    P set pid. as a result the pid program will be allowed to execute some operations like mount, unlink, chmod, chown etc.\n \
	    F set file. as a result the file can not be deleted.\n \
	    f get file. retrieve the setted protected file.\n");
}

static int check_caller_permission(int uid, int pid) {
    if (uid == 0) {
	return 0;
    }
    return 1;
}

static int accept_local_sock(int serv_fd)
{
    struct sockaddr_un sun;
    struct ucred creds;
    int fd = accept(serv_fd, NULL, NULL);
    if (fd < 0) {
	LOGE("accept error:%s", strerror(errno));
	return -1;
    }
	
    memset(&creds, 0, sizeof(creds));
    socklen_t size = sizeof(creds);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &creds, &size) == 0) {
	if (check_caller_permission(creds.uid, creds.pid) == 0) {
            return fd;
	}		
    }

    close(fd);	
    return -1;
}

static int create_local_sock()
{
    int fd;
    int len;
    struct sockaddr_un addr;  
    struct timeval tv;	

    fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
	LOGE("create Unix socket error:%s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    addr.sun_path[0] = '\0';
    strcpy(&addr.sun_path[1], LOCAL_SOCKET_NAME);

    int i;
    for (i = 0; i < 3; i++) {
	len = offsetof(struct sockaddr_un, sun_path) + strlen(LOCAL_SOCKET_NAME) + 1;
	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
	    LOGW("bind failed: %s", strerror(errno));
	    if (errno != EADDRINUSE) {
	        close(fd);
		return -1;
	    }
	    sleep(1);			
	} else {
	    if (listen(fd, 5) < 0) {
	        LOGE("listen error: %s", strerror(errno));
		    close(fd);
		    return -1;
	    }
	    break;
	}
    }

    return fd;
}

static int fill_pid(struct nlmsghdr *nlh, int pid) {        	
    int seq = get_rand();
    int payload = sizeof(struct __ctl_cmd); 
    int len = NLMSG_SPACE(payload);    
    nlh ->nlmsg_len = len;  
    nlh->nlmsg_pid = my_pid; 
    nlh->nlmsg_seq = seq;

    char *ctl = (char *)NLMSG_DATA(nlh);
    struct __ctl_cmd_base *ctl_base = (struct __ctl_cmd_base *)ctl;
    set_cmd_ver(ctl_base);
    CMD_OF_CTL(ctl_base) = CMD_SET_PID; 

    iov.iov_base = (void *)nlh;  
    iov.iov_len = nlh->nlmsg_len;  

    char *data = DATA_OF_CTL((struct __ctl_cmd *)ctl);
    *(int *)data = pid;
    return 0;
}

static int fill_file(struct nlmsghdr *nlh, char *file) {
    if (strlen(file) >= DATA_LEN) {
	return -1;
    }
    int seq = get_rand();
    int payload = sizeof(struct __ctl_cmd);
    int len = NLMSG_SPACE(payload);    
    nlh ->nlmsg_len = len;  
    nlh->nlmsg_pid = my_pid; 
    nlh->nlmsg_seq = seq;

    char *ctrl = (char *)NLMSG_DATA(nlh);
    struct __ctl_cmd_base *ctl_base = (struct __ctl_cmd_base *)ctrl;
    set_cmd_ver(ctl_base);
    CMD_OF_CTL(ctl_base) = CMD_SET_FILE; 

    iov.iov_base = (void *)nlh;  
    iov.iov_len = nlh->nlmsg_len;  

    char *data = DATA_OF_CTL((struct __ctl_cmd *)ctrl);
    strncpy(data, file, DATA_LEN);
    return 0;
}


static int parse_command(int fd, struct nlmsghdr *nlh) {
    char data[1024];
    int len = read(fd, data, sizeof(data)-1);
    if (len > 0) {
        data[len] = 0;
	char cmd = data[0];
	switch (cmd) {
	    case 'e':
		return CMD_EXIT;				
	    case 'O':
		return CMD_ENABLE_LSM;
	    case 'o':
		return CMD_DISENABLE_LSM;
	    case 'P':
		fill_pid(nlh, atoi(&data[1]));
		return CMD_SET_PID;
	    case 'F':
		if (fill_file(nlh, &data[1]) < 0) {
		    return -1;
		}
		return CMD_SET_FILE;
	    case 'f':
	        return CMD_GET_FILE;
					
	    }
	}
	return -1;
}

static int is_get_cmd(int cmd) {
    if (cmd == CMD_GET_FILE) {
        return 1;
    }
    return 0;
}

static void write_to_caller(int fd, char result, int cmd, struct nlmsghdr *nlh) {
    write(fd, &result, 1);
    if (result < 0) {
	close(fd);
	return;
    }

    if (is_get_cmd(cmd)) {
        struct __ctl_cmd *ctl = (struct __ctl_cmd *)NLMSG_DATA(nlh);
	char *data = DATA_OF_CTL(ctl);
	if (*data != 0) {
	    write(fd, data, ctl->len);
	} 
    }	
    close(fd);
}

static int is_exit_cmd(int cmd) {
    if (cmd == CMD_EXIT) {
        return 1;
    }
    return 0;
}
static int send_to_netlink(int fd, int cmd) {
    struct iovec *iov = (struct iovec *)msg.msg_iov;
    struct nlmsghdr *nlh = (struct nlmsghdr *)iov->iov_base;
    int seq = nlh->nlmsg_seq;	
	
    if (sendmsg(fd, &msg, MSG_DONTWAIT) < 0) {
        LOGE("sendmsg. error:%s\n", strerror(errno));
        return ERR_NETLINK_SEND;
    }

    if (!is_get_cmd(cmd)) {
	return 0;
    }

    int payload = sizeof(struct __ctl_cmd);
    int len = NLMSG_SPACE(payload);    
    memset(nlh, 0, len);
    if (recvmsg(fd, &msg, 0) < 0) {
        LOGE("recvmsg. error:%s\n", strerror(errno));
        return ERR_NETLINK_RECV;
    }

    if (check_rsp(cmd, nlh, seq) < 0) {
        return ERR_NETLINK_RSP;
    }
    return 0;    
}

static void bzero_nlh(struct nlmsghdr *nlh) {
    int payload = sizeof(struct __ctl_cmd);
    int len = NLMSG_SPACE(payload);
    memset(nlh, 0, len);
}

int main(int argc, char *argv[])
{
    my_pid = getpid();	
    struct nlmsghdr *nlh = init_nlh();
    if (nlh == 0) {
	exit(-1);			
    }
    int local_sock_fd = create_local_sock();
    if (local_sock_fd < 0) {
	free(nlh);
	exit(-1);
    }

    while (1) {		
	bzero_nlh(nlh);
	int caller_fd = accept_local_sock(local_sock_fd);
	if (caller_fd > 0) {
	    int cmd = parse_command(caller_fd, nlh);
	    if (cmd < 0) {
	        show_usage();
	        write_to_caller(caller_fd, ERR_INVALID_CMD, cmd, nlh);
	        continue;			
	    }
	    if (is_exit_cmd(cmd)) {
	        write_to_caller(caller_fd, 0, cmd, nlh);
	        break;			
	    }
	    int netlink_fd = init_netlink();
	    if (netlink_fd < 0) {
	        write_to_caller(caller_fd, ERR_NETLINK_INIT, cmd, nlh);
	        continue;
	    }
	    int result = send_to_netlink(netlink_fd, cmd);
	    write_to_caller(caller_fd, result, cmd, nlh);
	    close(netlink_fd);
        }	    	
    }

    close(local_sock_fd);
    free(nlh);
    return 0;	
}





