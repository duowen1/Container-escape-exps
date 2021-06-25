# 1 介绍

一些能够导致容器逃逸的EXP以及使用介绍，所有的exp都是经过本地验证的。

# 2 漏洞列表

漏洞|描述|验证
---|---|---
[CVE-2020-15257](./CVE-2020-15257/readme.md)|Containerd组件漏洞逃逸|验证中
[CVE-2019-14271](./CVE-2019-14271/readme.md)|Docker组件漏洞逃逸|已验证
[CVE-2019-5736](./CVE-2019-5736/readme.md)|Runc漏洞逃逸|已验证
[CVE-2017-7308](./CVE-2017-7308/readme.md)|内核漏洞逃逸|已验证
[CVE-2016-5795](./CVE-2016-5795/readme.md)|内核漏洞逃逸|已验证
[CVE-2018-18955](./CVE-2018-18955/readme.md)|内核漏洞提权|已验证

# 3 总结

1. `--privileged`选项等同于将宿主机暴露给容器，可以完全绕过mnt namespace的限制，也可以进一步通过挂接`/proc`的方式绕过pid namespace。
2. 和虚拟机相比，容器存在更多的逃逸攻击面：
	1.  系统内核的漏洞
	2.  容器组件本身的漏洞
	3.  错误的配置
3. 和虚拟机相比，容器逃逸攻击成分非常低
	1. 更多逻辑漏洞，无需考虑内存布局即可逃逸（CVE-2019-5736 Poc仅60行go代码
    2. 在错误的配置下，无需代码即可完成逃逸 
4. 和虚拟机相比，容器逃逸的形式更加灵活
	1. 由于隔离机制的分散性，逃逸往往不需要对于所有隔离机制的破解（大部分只需要对chroot进行bypass，必要时对pid namespace进行exploit）
	2. 依然由于隔离机制的分散性，存在木桶效应