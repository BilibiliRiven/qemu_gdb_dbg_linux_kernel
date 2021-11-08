# Linux内核调试环境搭建
偶尔要分析一下Linux内核，内核探针有时并不能满足需要（例如调试分析CVE）。采用VM虚拟机通过管道加IDA双机调试很卡，调试体验很差。用KDB双机调试也是卡，有时还会断点无效，死机也是常事。Visual Studio调试内核依然不方便，重点是卡慢。最终还是学习Google使用QEMU调试内核。（网上一大推调试文章，能用好用的并不多，我跟着一路折腾过来真把我弄得够呛。给后来人一个忠告，老老实实在开启虚拟化的Linux虚拟机中使用QEMU+gdb）

# 靠谱点的资料
多读牛逼人的一手资料，官方文档。每次找资料真找的我血压升高。
下面文档高质量的有google的文章，和jiayy的文章还有看雪的文章。
```
https://www.starlab.io/blog/using-gdb-to-debug-the-linux-kernel
https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md
https://www.kernel.org/doc/html/latest/dev-tools/gdb-kernel-debugging.html
https://bbs.pediy.com/thread-252344.htm
http://jiayy.me/2020/05/13/qemu+gdb+kernel/
```
## 我的环境搭建过程
### Ubuntu安装VMTool
拷贝vmare-tools-distrib到桌面。
运行tar -zxvf解压
运行sudo ./vmare-install.ph
```
### 修复不能从桌面拷贝的问题
sudo apt-get install open-vm-tools-desktop
### 能选Yes就Yes，剩下一路默认就好
```
### 修改Ubuntu源
获取Codename
```
lsb_release -a
```
将TODO替换成Codename
```
deb http://mirrors.aliyun.com/ubuntu/ TODO main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ TODO main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ TODO-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ TODO-security main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ TODO-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ TODO-updates main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ TODO-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ TODO-proposed main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ TODO-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ TODO-backports main restricted universe multiverse
```
替换后格式如下
```
deb http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-security main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-updates main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-proposed main restricted universe multiverse

deb http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ focal-backports main restricted universe multiverse
```
更新软件列表
```
sudo apt update
```
### 编译Linux内核
环境准备
```
# make menuconfig的相关依赖
sudo apt install libncurses-dev
sudo apt install flex
sudo apt install bison
# make 编译需要
sudo apt install build-essentail # 可能不需要
sudo apt install libssl-dev
sudo apt install libelf-dev
```
```
make defconfig kvm_guest.config
make menuconfig
#CONFIG_GDB_SCRIPTS=enabled
#CONFIG_DEBUG_INFO_REDUCED =off
#CONFIG_FRAME_POINTER=enabled
#CONFIG_RANDOMIZE_BASE=off

```
```
make bzImage -j$(nproc) && make vmlinux -j$(nproc)
```

## 配置QEMU虚拟机
```
sudo apt install qemu
sudo apt install qemu-system-x86
```
```
qemu-system-x86_64   \
-smp 4 \
-enable-kvm -m 2G -nographic \
-kernel /path-to/linux/arch/x86/boot/bzImage  \
-append "console=ttyS0 root=/dev/sda earlyprintk=serial rw nokaslr"  \
-drive file=/path-to/focal.img,format=raw   \
-device e1000,netdev=t0  \
-pidfile vm.pid \
-netdev user,id=t0,hostfwd=tcp::10022-:22 -s -S  
```

### 配置wget代理
能访问外网的实验室就不用了。
```
/etc/wgetrc
#You can set the default proxies for Wget to use for http, https, and ftp.
# They will override the value in the environment.
https_proxy = http://127.0.0.1:7890/
http_proxy = http://127.0.0.1:7890/
ftp_proxy = http://127.0.0.1:7890/

# If you do not want to use proxy at all, set this to off.
use_proxy = on
```

### 配置磁盘镜像
安装debootstrap
```
sudo apt install debootstrap
```

通过debootstrap构建ubuntu镜像。
```
#!/bin/bash
# create-image.sh creates a minimal ubuntu image suitable for kernel debugging.
# Copyright 2020 chengjia4574@gmail.com（修改了一点点）

set -eux

#RELEASE=eoan  # ubuntu19.10
RELEASE=focal # ubuntu20.04

DIR=chroot-$RELEASE
sudo rm -rf $DIR
sudo mkdir -p $DIR
sudo chmod 0755 $DIR

INSTALL_PKGS=openssh-server,curl,tar,gcc,libc6-dev,time,strace,sudo,less,psmisc,net-tools,build-essential,vim,git,make

sudo debootstrap --include=$INSTALL_PKGS --components=main,contrib,non-free $RELEASE $DIR

# Set some defaults and enable promtless ssh to the machine for root.
sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd
echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
# 必须关闭 kaslr 才可以正常调试内核
echo 'GRUB_CMDLINE_LINUX_DEFAULT="nokaslr"' | sudo tee -a $DIR/etc/default/grub
# /etc/network/interfaces 已经被 ubuntu 放弃，改为了　netplan 方式
printf 'network:\n version: 2\n renderer: networkd\n ethernets:\n enp0s3:\n dhcp4: true\n' | sudo tee -a $DIR/etc/netplan/01-network-manager-all.yaml
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'binfmt_misc /proc/sys/fs/binfmt_misc binfmt_misc defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a $DIR/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_kallsyms = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.softlockup_all_cpu_backtrace = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.kptr_restrict = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.watchdog_thresh = 60" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a $DIR/etc/sysctl.conf
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolve.conf
echo "jiayy" | sudo tee $DIR/etc/hostname
ssh-keygen -f $RELEASE.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
cat $RELEASE.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys

# Build a disk image
dd if=/dev/zero of=$RELEASE.img bs=1G seek=20 count=1
sudo mkfs.ext4 -F $RELEASE.img
sudo mkdir -p /mnt/$DIR
sudo mount -o loop $RELEASE.img /mnt/$DIR
sudo cp -a $DIR/. /mnt/$DIR/.
sudo umount /mnt/$DIR

```

采用google方法构建Debian Stretch Linux镜像(原理一样)
前期不要纠结脚本内容以及含义快点把这步过去早点开始调试Linux内核。
```
mkdir $IMAGE
cd $IMAGE/
sudo wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
chmod +x create-image.sh
./create-image.sh
```

## 启动Qemu虚拟机
```
qemu-system-x86_64 \
	-m 2G \
	-smp 2 \
	-kernel $KERNEL/arch/x86/boot/bzImage \
	-append "console=ttyS0 root=/dev/sda earlyprintk=serial net.ifnames=0" \
	-drive file=$IMAGE/stretch.img,format=raw \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22 \
	-net nic,model=e1000 \
	-enable-kvm \
	-nographic \
	-pidfile vm.pid \
	2>&1 | tee vm.log
```

## 安装gef
如果公司没有代理，就手动下载gdbinit-gef.py，执行命令。
不过最好提前先备份~/.gdbinit。
```
$ wget -O ~/.gdbinit-gef.py -q http://gef.blah.cat/py
$ echo source ~/.gdbinit-gef.py >> ~/.gdbinit
```
