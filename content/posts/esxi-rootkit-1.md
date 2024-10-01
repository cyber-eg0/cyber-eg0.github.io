+++
title = 'ESXHiDE - ESXi Rootkit Development - Part 1'
date = 2024-09-29T10:19:57-05:00
draft = true
+++

## Introduction

For some time now, I've been told that ESXi VMkernel is **NOT** Linux.  After some research into developing user mode (or user world, as VMware calls it) tools, I finally understood what that meant.  I won't be going into all of the differences in this series but for those who are curious, [this whitepaper on ESXi architecture](https://microage.com/wp-content/uploads/2016/02/ESXi_architecture.pdf) is a good starting point.  My mind started to drift away from user mode tools to kernel mode security tools.  The only real resources I was able to find online were those related to things like USB and NIC drivers.  VMkernel is able to run some Linux kernel modules, but not all.  This series will go into my research and methods on creating a proof-of-concept rootkit called ESXHiDE on ESXi VMkernel to intercept system calls.

## Execution Environment Setup

My setup is a Windows 11 host machine with VMware Workstation running a Ubuntu 22.04 VM and VMware ESXi 6.7 (Build 14320388) VM.

```
Windows 11
    VMware Workstation
        Ubuntu 22.04
        ESXi 6.7 Build 14320388
        CentOS 7
```

To enable debugging on the ESXi VM through Workstation, I appended the following to `<ESXi VM>.vmx`:

```
debugStub.listen.guest64 = "TRUE"
```

If all goes well, `vmware.log` will show that debugging is enabled and listening on a port.

```
vmx Debug stub: VMware Workstation is listening for debug connection on port 8864.
vmx Debug stub:     (gdb) target remote localhost:8864
```

For me, this was on port 8864 on my Windows 11 host.  However, because I wanted to work on my Ubuntu VM, I used SSH to create tunnel from my Windows host so port 8864 on my VM could reach the debug port.

```
ssh -R 8864:localhost:8864 <user>@<ubuntu_vm_ip>
```

Once that's set up, GDB is good to connect and I was ready to get to work.

## Development Environment Setup

Although VMware recommends CentOS 5 as one of the build environments, I chose CentOS 7 and hadn't run into any issues.  I opted to use the CentOS repository for the following tools instead of building ESXi's toolchain:

```
GCC 4.8.5
GLIBC 2.17
```

I also grabbed the VMkernel files to be able to compile a kernel module.

However, I'm also picky about my environment, so I used the `Rmeote SSH` plugin for VSCode to do my work from my Ubuntu VM.


## Verification

To see if my execution environment was properly set up, I attached GDB to the ESXi kernel.

![gdb](/images/2024-09-29-10-48-58.png)

To see if my development environment was properly set up, I compiled a simple kernel module to print "Hello World".

```
# vmkload is a native binary on ESXi to load in modules
# vmkload -u can be used to unload modules
vmkload esxhide

# view kernel messages
dmesg
...
2024-09-29T16:01:25.235Z cpu1:2103549)Loading module esxhide ...
2024-09-29T16:01:25.236Z cpu1:2103549)module heap vmklnx_esxhide: creation succeeded. id = 0x43049c224000
2024-09-29T16:01:25.236Z cpu1:2103549)<6>Hello World from ESXHiDE
...
```