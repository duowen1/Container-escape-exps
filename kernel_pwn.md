可以参考[CTF wiki](https://ctf-wiki.org/pwn/linux/kernel-mode/basic-knowledge/)

# 防御机制

## SMAP&SMEP


## KASLR

### 查看内核地址

```bash
cat /proc/kallsyms | grep <需要查找的符号>
```

如果有vmlinux文件：
```bash
nm vmlinux | grep <需要查找的符号>
```

# 攻击手段

## 堆喷射

## ROP

面向返回的编程

1. 安装ROPgadget
[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)


# 提权思路

## `commit_creds(prepare_kernel_cred(0))`

# 逃逸思路

# 调试环境
详见[构建调试环境](./debug.md)

# 参考链接
- [How to build Linux kernel from scratch](https://phoenixnap.com/kb/build-linux-kernel)