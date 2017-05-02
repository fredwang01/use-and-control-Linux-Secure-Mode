## ======use and control Linux Secure Mode=======

Linux secure mode(LSM) is a kind of security mechanism which can limit to execute some sensitive operations no matter what user is. LSM provide some hook functions to check if the current process can be allowed to execute these sensitive operations like `chmod`, `chown`, `unlink`, `rm`, `mount` and so on.

**Compile the custom LSM into kernel**

I compile my custom LSM into kernel source code based on version 2.6, below is the steps about how to compile the custom LSM:

* First of all, prepare a copy of linux source code, and then create a directory named my_lsm(any name you like) in the security directory of the linux souce code, put the three files `Makefile`, `caphook.h` and `paccess.c` in my_lsm directory.

* Edit and save the Makefile in the security, add the following two lines:
  ```
  subdir-y += my_lsm  
  obj-y += my_lsm/built-in.o
  ```
* Edit and save the file `include/linux/netlink.h`, add the following line:
   ```
   #define NETLINK_MYLSM  25
   ```
   make sure this macro's value do not override the existed netlink number.

* Run `make menuconfig` at the root directory of kernel to configure compilation options.
 in the pop-up window of `security options`, select these options:
   ```
   Enable different security models
   Enable the securityfs filesystem
   Security hooks for pathname based access control
   ```
   and in the `Default  security module`, select the option:
   ```
   Unix Discretionary Access Control
   ```
   save and exit.

* Run `make` at the root directory of kernel to compile linux source code, and you will get the OS image if successed.

**Control the LSM behaviour**

A proxy process(`uctl.c`) in user space receive the command from the caller to control the custom LSM behaviour like disable/enable LSM, set the protected file or process and so on. the following figure involved the three entities about LSM control command.
```
  +----------------+   Unix socket   +---------------+
  | caller process | <-------------> | proxy process |    User space
  +----------------+                 +---------------+
                                             ^ NETLINK socket
  -------------------------------------------|-----------------------
                                             |            kernel space
                                             v
                                     +---------------+
                                     |    my LSM     |
                                     +---------------+
```


