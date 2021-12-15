# 0x01 介绍

收集一些能够导致容器逃逸的EXP，有一部分经过了的改造。尽可能清楚地从底层介绍了漏洞的原理以及利用思路，所有的exp都是经过本地验证的。

# 0x02 漏洞列表

漏洞|描述|验证
---|---|---
[CVE-2021-22555](./CVE-2021-22555/readme.md)|内核漏洞逃逸|已验证
[CVE-2020-15257](./CVE-2020-15257/readme.md)|Containerd组件漏洞逃逸|已验证
[CVE-2019-14271](./CVE-2019-14271/readme.md)|Docker组件漏洞逃逸|已验证
[CVE-2019-5736](./CVE-2019-5736/readme.md)|Runc漏洞逃逸|已验证
[CVE-2017-7308](./CVE-2017-7308/readme.md)|内核漏洞逃逸|已验证
[CVE-2016-5195](./CVE-2016-5195/readme.md)|内核漏洞逃逸|已验证
[CVE-2018-18955](./CVE-2018-18955/readme.md)|内核漏洞提权|已验证
[CVE-2018-15664](./CVE-2018-15664/readme.md)|Docker Daemon漏洞逃逸|已验证

# 0x03 一些错误配置导致的逃逸

错误配置|描述|验证
---|---|---
[--privileged](./特权容器/readme.md)|特权容器导致的逃逸|已验证
[Shocker](./Shocker/readme.md)|CAP_DAC_READ_SEARCH错误配置|已验证
[未授权访问](./未授权访问.md)|docker remote api未授权访问|未验证
[不当挂载](./不当挂载.md)|docker.sock挂载到容器内部|未验证

# 0x04 一些容器基本知识
机制|说明
---|---|
Namespace|提供多种资源的隔离
Cgroup|Linux Control Groups，分为v1和v2，主要限制进程可使用的资源
Capability|根据最小权限原则设计的限制特权进程的能力的机制，漏洞防御最为有效的手段
Seccomp|限制进程能够使用的系统调用
UnionFS|联合文件系统系统，Docker通过联合文件系统实现镜像功能

# 0x05 总结

1. `--privileged`选项等同于将宿主机暴露给容器，可以完全绕过mnt namespace的限制，也可以进一步通过挂接`/proc`的方式绕过pid namespace。
2. 和虚拟机相比，容器存在更多的逃逸攻击面：
	1.  系统内核的漏洞
	2.  容器组件本身的漏洞
	3.  错误的配置
3. 和虚拟机相比，容器逃逸攻击成本非常低
	1. 更多逻辑漏洞
    2. 在错误的配置下，攻击无需绕过任何防御机制
4. 和虚拟机相比，容器逃逸的形式更加灵活
	1. 由于隔离机制的分散性，逃逸往往不需要对于所有隔离机制的破解
	2. 各个隔离机制存在木桶效应

# 0x06 环境搭建

- 参考[Metarget](https://github.com/brant-ruan/metarget)

# 0x07 漏洞利用工具
- [CDK](https://github.com/cdk-team/CDK)