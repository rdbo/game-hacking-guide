# Linux Game Hacking  
  
# 0.1 - Introduction  
Linux game hacking is an unpopular topic, possibly because Linux is not very much used in personals desktops, but also because a lot of games don't run natively on it. Due to this limitations, I had a hard time figuring it all out, but I finally did it. This guide will use C++ to make everything more simple, but my <a href="https://github.com/rdbo/libmem">main game hacking framework (libmem)</a> is written in C and supports Windows and Linux, in case you're interested. This guide will also not have much error checking, because it is meant to be simple and straightforward. Anyways, let's get started. The sections '1.X' will be dedicated to external game hacking and the sections '2.X' will be dedicated to internal game hacking.  

# 0.2 - But before...  
This tutorial contains a lot of information, some of which you may have no knowledge about. Anything you don't understand from the Linux headers, you can check the man page of this X thing you don't know and it will give you a very detailed information about it, including return type, arguments, bugs, etc.
Also, you may want to make sure you have the proper Linux headers installed, a compiler like GCC or CLANG, and you may want to run every one of your tests as root.  
  
# 0.3 - Writing code for x86/x64  
  
There are certain stuff we're going to use on this guide where x86 differs from x64. To make sure no problem happens, we're going to define macros that allows us to writing different code for each architecture. In case you're interested in ARM, this tutorial will not cover it specifically, but you can still go through it without having major problems. Here are the macros and includes we're going to use on this guide:  
```c++
#include <iostream>
#include <cstring>
#include <sstream>
#include <istream>
#include <fstream>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/io.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>

#if defined(_M_IX86) || defined(__i386__) || __WORDSIZE == 32
#define ARCH_86 /* The code is being compiled for 32 bits */
#elif defined(_M_X64) || defined(__LP64__) || defined(_LP64) || __WORDSIZE == 64
#define ARCH_64 /* The code is being compiled for 64 bits */
#endif

/* Helper macros */
#if defined(ARCH_86)
#define strtoptr(nptr, endptr, base) strtoul(nptr, endptr, base)
#elif defined(ARCH_64)
#define strtoptr(nptr, endptr, base) strtoull(nptr, endptr, base)
#endif
```
  
# 1.0 - Handling an external process  
  
On Linux, just like on Windows, each process has its own ID, which I am going to refer to from now on as 'PID' (Process ID). For every process that is launched, a folder is created at '/proc' containing a lot of process information. This folder is very important, because it constains a lot of valuable information that we're going to use, and it is named with the PID of the launched process, so the absolute path would be '/proc/\<pid\>'. The first thing we're going to get a process's ID base on its name.
As I mentioned, the folder '/proc/\<pid\>' contains a lot of good information, including a file called 'cmdline', which stores the command line used to run the process. As every PID is listed on '/proc', we can loop through every folder there, read the command line, parse it, and then compare it to the process name that was input. Here's a commented function that will do the job for us:  
```c++
pid_t get_process_id(std::string process_name)
{
    pid_t pid = (pid_t)-1;
    DIR* pdir = opendir("/proc"); //Open directory stream
	if (!pdir)
		return pid;

    if(process_name.back() != '\0') process_name += '\0'; //Making sure the null terminator is there

	struct dirent* pdirent; //Directory structure entry
	while (pid == -1 && (pdirent = readdir(pdir)))
	{
		pid_t id = (pid_t)atoi(pdirent->d_name);
		if (id > 0)
		{
            std::stringstream cmd_line_path;
            cmd_line_path << "/proc/";
            cmd_line_path << id;
            cmd_line_path << "/cmdline";

            /* cmd_line_path's string now should be: /proc/<id>/cmdline
             * we're going to use it to read the cmdline file's content through
             * a file stream.
             */

            std::cout << "Command Line Path: " << cmd_line_path.str() << std::endl;

            std::ifstream cmd_line_fs(cmd_line_path.str(), std::ios::binary); //Open file stream of /proc/<id>/cmdline
            if(!cmd_line_fs.is_open()) continue;

            //Store the content of the cmdline file into 'cmd_line'
            std::stringstream cmd_line;
            cmd_line << cmd_line_fs.rdbuf();
            /* Now, let's parse the cmd_line string to get the process name */

            std::cout << "Command Line: " << cmd_line.str() << std::endl;

            size_t proc_name_pos = cmd_line.str().rfind('/') + 1; /*Find the position of the last '/', 
                                                                        as it will be followed by the process name */

			std::string cur_process_name = cmd_line.str().substr(proc_name_pos); /* Get a substring of the cmd_line that 
                                                                                        goes from the slash position to the end of the string */

            if(cur_process_name.back() != '\0') cur_process_name += '\0'; //Making sure the null terminator is there

            cmd_line_fs.close(); //Close file stream

            std::cout << "Current Process Name: " << cur_process_name << std::endl;

			if (!strcmp(process_name.c_str(), cur_process_name.c_str())) //Compare the current process name with the one we want
            {
                pid = id;
                std::cout << "Process ID found: " << pid << std::endl;
                break;
            }

            std::cout << "--------------------" << std::endl;
		}
	}

	closedir(pdir); //Close directory stream

    return pid;
}

```
  
Example:  
```c++
int main()
{
    pid_t pid = get_process_id("target");
    std::cout << "PID of target: " << pid << std::endl;
    return 0;
}
```  
  
Output:  
```
...

Command Line Path: /proc/9874/cmdline
Command Line: 
Current Process Name: 
--------------------
Command Line Path: /proc/9890/cmdline
Command Line: 
Current Process Name: 
--------------------
Command Line Path: /proc/9918/cmdline
Command Line: ./target
Current Process Name: target
Process ID found: 9918
PID of target: 9918
```  
  
# 1.1 - Reading / Writing memory  
  
Now that we can get a process's ID, we can do all kinds of stuff with it, including reading and writing memory, injecting calls (later), and much more. There are various ways of reading and writing memory on Linux, we can mention the one using ptrace (we're not gonna use this one for now, because it requires attaching to the process and doing so will freeze it until we continue the execution), and there's also another one using 2 simple functions: process_vm_readv and process_vm_writev (I discovered them by accident on the man page).
To read memory, we have to use 'process_vm_readv' and tell it where to read on the target process, where to store on the caller process (you can get more info on the man page). Let's make a function for it:  
```c++
void read_memory(pid_t pid, void* src, void* dst, size_t size)
{
    /*
    pid  = target process id
    src  = address to read from on the target process
    dst  = address to write to on the caller process
    size = size of the buffer that will be read
    */

    struct iovec iosrc;
	struct iovec iodst;
	iodst.iov_base = dst;
	iodst.iov_len  = size;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;

    process_vm_readv(pid, &iodst, 1, &iosrc, 1, 0);
}
```  
  
```c++
void write_memory(pid_t pid, void* dst, void* src, size_t size)
{
    /*
    pid  = target process id
    dst  = address to write to on the target process
    src  = address to read from on the caller process
    size = size of the buffer that will be read
    */

    struct iovec iosrc;
	struct iovec iodst;
	iosrc.iov_base = src;
	iosrc.iov_len  = size;
	iodst.iov_base = dst;
	iodst.iov_len  = size;

    process_vm_writev(pid, &iosrc, 1, &iodst, 1, 0);
}
```  
  
Example:  
```c++
int main()
{
    pid_t pid = get_process_id("target");
    void* address = (void*)0x557d498b5068; //This is just an address I got manually from a dummy target process
    int buffer = 1337;
    write_memory(pid, address, &buffer, sizeof(buffer));

    int read_buffer;
    read_memory(pid, address, &read_buffer, sizeof(read_buffer));
    std::cout << "Read buffer (should be 1337): " << read_buffer << std::endl;
    return 0;
}
```  
  
Output:  
```
...
--------------------
Command Line Path: /proc/10478/cmdline
Command Line: ./target
Current Process Name: target
Process ID found: 10478
Read buffer (should be 1337): 1337
```  
  
# 1.2 - Getting a loaded module information  
On Linux, processes use shared libraries just like on Windows they use DLLs. One these shared libraries are loaded, we can get some information about them using the file '/proc/\<pid\>/maps', which contains information about all the loaded modules, and some extras, like stack and heap. This information can be used to access certain variables and values through offsets that are based off a module. This part is a little bit longer because it requires a lot of parsing of the maps file and we will also create a new type for our module information to make it easier to use. The information we will get is going to be: base address, size, end address, module name, module path. So let's make a corresponding structure with this information:  
```c++
typedef struct _module_t
{
    std::string name;
    std::string path;
    void*       base;
    void*       end;
    uintptr_t   size;
    void*       handle; //this will not be used for now, only internally with dlopen
}module_t;
```  
  
Now, let's understand the maps file.  
```
7f2a4aa04000-7f2a4aa2a000 r--p 00000000 08:01 27793503                   /usr/lib/libc-2.32.so
7f2a4aa2a000-7f2a4ab77000 r-xp 00026000 08:01 27793503                   /usr/lib/libc-2.32.so
7f2a4ab77000-7f2a4abc3000 r--p 00173000 08:01 27793503                   /usr/lib/libc-2.32.so
7f2a4abc3000-7f2a4abc6000 r--p 001be000 08:01 27793503                   /usr/lib/libc-2.32.so
7f2a4abc6000-7f2a4abc9000 rw-p 001c1000 08:01 27793503                   /usr/lib/libc-2.32.so
```  
  
The module is split in multiple regions due to different protection flags. Each line is a region and it reads like this:
`base_address-end_address protection_flags offset dev inode module_path`
For this section of the guide, we're going to get the first base_address (in this case, 0x7f2a4aa04000), the last end address (in this case, 0x7f2a4abc9000) and the module path (in this case, /usr/lib/libc-2.32.so). The module name and size can be gotten through these other values.
Now, let's make a function that parses the maps file of a process and then returns a module_t structure with all the information. The module will be gotten through its name or path. Also, we're going to get the closest match, so that you'll be able to get modules that have different versions on different OS's.  
  
```c++
module_t get_module(pid_t pid, std::string module_name)
{
    module_t mod;

    std::stringstream maps_file_path;
    maps_file_path << "/proc/" << pid << "/maps"; //Get maps file path
    std::cout << "Maps file path: " << maps_file_path.str() << std::endl;

    std::ifstream maps_file_fs(maps_file_path.str(), std::ios::binary); //Open maps file stream
    if(!maps_file_fs.is_open()) return mod;

    std::stringstream maps_file;
    maps_file << maps_file_fs.rdbuf(); //Read the content of the maps file

    //--- Module Path

    size_t module_path_pos = 0;
    size_t module_path_end = 0;
    std::string module_path_str;

    //Get the first slash in the line of the module name
    module_path_pos = maps_file.str().find(module_name);
    size_t holder = module_path_pos;
    module_path_pos = maps_file.str().rfind('\n', module_path_pos);
    if(module_path_pos == maps_file.str().npos) //If it's invalid, try another method
        module_path_pos = maps_file.str().rfind("08:01", holder); //The 'dev' of every module is '08:01', so we can use it as a filter
    module_path_pos = maps_file.str().find('/', module_path_pos);

    //Get the end of the line of the module name
    module_path_end = maps_file.str().find('\n', module_path_pos);

    if(module_path_pos == maps_file.str().npos || module_path_end == maps_file.str().npos) return mod;

    //Module path substring
    module_path_str = maps_file.str().substr(module_path_pos, module_path_end - module_path_pos);

    std::cout << "Module path string: " << module_path_str << std::endl;

    //--- Module name

    std::string module_name_str = module_path_str.substr(
        module_path_str.rfind('/') + 1 //Substring from the last '/' to the end of the string
    );

    std::cout << "Module name: " << module_name_str << std::endl;

    //--- Base Address

    size_t base_address_pos = maps_file.str().rfind('\n', module_path_pos) + 1;
    size_t base_address_end = maps_file.str().find('-', base_address_pos);
    if(base_address_pos == maps_file.str().npos || base_address_end == maps_file.str().npos) return mod;
    std::string base_address_str = maps_file.str().substr(base_address_pos, base_address_end - base_address_pos);
    base_address_str += '\0'; //Making sure the null terminator is there
    void* base_address = (void*)strtoptr(base_address_str.c_str(), NULL, 16);
    std::cout << "Base Address: " << base_address << std::endl;

    //--- End Address
    size_t end_address_pos;
    size_t end_address_end;
    std::string end_address_str;
    void* end_address;

    //Get end address pos
    end_address_pos = maps_file.str().rfind(module_path_str);
    end_address_pos = maps_file.str().rfind('\n', end_address_pos) + 1;
    end_address_pos = maps_file.str().find('-', end_address_pos) + 1;

    //Find first space from end_address_pos
    end_address_end = maps_file.str().find(' ', end_address_pos);

    if(end_address_pos == maps_file.str().npos || end_address_end == maps_file.str().npos) return mod;

    //End address substring
    end_address_str = maps_file.str().substr(end_address_pos, end_address_end - end_address_pos);
    end_address_str += '\0';
    end_address = (void*)strtoptr(end_address_str.c_str(), NULL, 16);

    std::cout << "End Address: " << end_address << std::endl;

    //--- Module size

    uintptr_t module_size = (uintptr_t)end_address - (uintptr_t)base_address;
    std::cout << "Module Size: " << (void*)module_size << std::endl;

    //---

    //Now we put all the information we got into the mod structure

    mod.name = module_name_str;
    mod.path = module_path_str;
    mod.base = base_address;
    mod.size = module_size;
    mod.end  = end_address;

    maps_file_fs.close();

    return mod;
}
```  
  
Maps file:  
```
5575192e3000-5575192e4000 r--p 00000000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
5575192e4000-5575192e5000 r-xp 00001000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
5575192e5000-5575192e6000 r--p 00002000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
5575192e6000-5575192e7000 r--p 00002000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
5575192e7000-5575192e8000 rw-p 00003000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
55751b24d000-55751b26e000 rw-p 00000000 00:00 0                          [heap]
...
```  
  
Example:  
```c++
int main()
{
    pid_t pid = get_process_id("target");
    module_t mod = get_module(pid, "target");
    return 0;
}
```  
  
Output:  
```
...
--------------------
Command Line Path: /proc/3845/cmdline
Command Line: ./target
Current Process Name: target
Process ID found: 3845
Maps file path: /proc/3845/maps
Module path string: /home/rdbo/Documents/Codes/C/linux_gh/target
Module name: target
Base Address: 0x5575192e3000
End Address: 0x5575192e8000
Module Size: 0x5000
```  
  
GDB Output:  
`(gdb) print mod`  
`$1 = {name = "target", path = "/home/rdbo/Documents/Codes/C/linux_gh/target", base = 0x5575192e3000, end = 0x5575192e8000, 
  size = 20480, handle = 0x0}`  
  
# 1.3 - Injecting syscalls  
  
Linux has something called 'ptrace', which is a syscall that allows us to control the execution flow of another process, the tracee, as a tracer (check out the man page for very detailed info). Before going further, let's understand Linux syscalls. Every syscall has a number that represents its action, and a syscall can have up to 5 arguments (arg0-arg5).  
On 32 bits, these arguments are stored like this:  
```
eax - syscall number
ebx - arg0
ecx - arg1
edx - arg2
esi - arg3
edi - arg4
ebp - arg5
```  
On 64 bits:  
```
rax - syscall number
rdi - arg0
rsi - arg1
rdx - arg2
r10 - arg3
r8  - arg4
r9  - arg5
```  
The return value of the syscall is stored in EAX/RAX.  
  
To inject a syscall, we're going to write our injection buffer in the EIP/RIP register (which is always executable, unless something goes wrong on the process normal execution), get the return value, and then restore the original execution.
Let's make a function that does so.  
```c++
void* inject_syscall(
    pid_t pid, 
    int syscall_n, 
    void* arg0, 
    void* arg1, 
    void* arg2, 
    void* arg3, 
    void* arg4, 
    void* arg5
){
    void* ret = (void*)-1;
    int status;
    struct user_regs_struct old_regs, regs;
    void* injection_addr = (void*)-1;

    //This buffer is our payload, which will run a syscall properly on x86/x64
    unsigned char injection_buf[] =
    {
#       if defined(ARCH_86) //32 bits syscall
        0xcd, 0x80, //int80 (syscall)
#       elif defined(ARCH_64) //64 bits syscall
        0x0f, 0x05, //syscall
#       endif
        /* these nops are here because
         * we're going to write memory using
         * ptrace, and it always writes the size
         * of a word, which means we have to make
         * sure the buffer is long enough
        */
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90, //nop
		0x90  //nop
    };

    //As ptrace will always write a uintptr_t, let's make sure we're using proper buffers
    uintptr_t old_data;
    uintptr_t injection_buffer;
    memcpy(&injection_buffer, injection_buf, sizeof(injection_buffer));

    //Attach to process using 'PTRACE_ATTACH'
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(&status);

    /* Get the current registers using 'PTRACE_GETREGS' so that
     * we can restore the execution later
     * and also modify the bytes of EIP/RIP
    */

    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    regs = old_regs;

    //Now, let's set up the registers that will be injected into the tracee

#   if defined(ARCH_86)
    regs.eax = (uintptr_t)syscall_n;
    regs.ebx = (uintptr_t)arg0;
    regs.ecx = (uintptr_t)arg1;
    regs.edx = (uintptr_t)arg2;
    regs.esi = (uintptr_t)arg3;
    regs.edi = (uintptr_t)arg4;
    regs.ebp = (uintptr_t)arg5;
    injection_addr = (void*)regs.eip;
#   elif defined(ARCH_64)
    regs.rax = (uintptr_t)syscall_n;
    regs.rdi = (uintptr_t)arg0;
    regs.rsi = (uintptr_t)arg1;
    regs.rdx = (uintptr_t)arg2;
    regs.r10 = (uintptr_t)arg3;
    regs.r8  = (uintptr_t)arg4;
    regs.r9  = (uintptr_t)arg5;
    injection_addr = (void*)regs.rip;
#   endif

    //Let's store the buffer at EIP/RIP that we're going to modify into 'old_data' using 'PTRACE_PEEKDATA'
    old_data = (uintptr_t)ptrace(PTRACE_PEEKDATA, pid, injection_addr, NULL);

    //Let's write our payload into the EIP/RIP of the target process using 'PTRACE_POKEDATA'
    ptrace(PTRACE_POKEDATA, pid, injection_addr, injection_buffer);

    //Let's inject our modified registers into the target process using 'PTRACE_SETREGS'
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    //Let's run a single step in the target process (execute one assembly instruction)
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, &status, WSTOPPED); //Wait for the instruction to run

    //Let's get the registers after the syscall to store the return value
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
#   if defined(ARCH_86)
    ret = (void*)regs.eax;
#   elif defined(ARCH_64)
    ret = (void*)regs.rax;
#   endif

    //Let's write the old data at EIP/RIP
    ptrace(PTRACE_POKEDATA, pid, (void*)injection_addr, old_data);

    //Let's restore the old registers to continue the normal execution
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL); //Detach and continue the execution

    return ret;
}
```  
  
Example:  
```c++
int main()
{
    pid_t pid = get_process_id("target");
    module_t mod = get_module(pid, "target");
    inject_syscall(pid, __NR_exit, (void*)-1, NULL, NULL, NULL, NULL, NULL); //This will force the target process to exit with code -1
    return 0;
}
```  
  
Output:  
```
PID: 6010
Waiting...
Address: 0x5608bac84068
Value: 10
$ echo $? #This prints the last exit code (which should be -1, if everything went fine)
255 #This is -1, but as an unsigned char.
```  
  
# 1.4 - Protecting/Allocating/Deallocating Memory  
  
On the previous section, we learned how to inject syscalls. There are certain syscalls that are very usefull for us, such as \__NR_mmap, \__NR_mmap2, \__NR_mprotect, \__NR_munmap.  
  
\__NR_mmap and \_NR_mmap2 (for 32 bits) run the function mmap, which can be used to allocate memory.  
\__NR_munmap runs the function munmap, which can be used to deallocate memory.  
\__NR_mprotect runs the function mprotect, which can be used to change the protection flags of a memory region.  
Check the man page for the functions above to understand them better.  
  
Now that we have a function to inject syscalls, making these functions will not be any problem:  
```c++
void* allocate_memory(pid_t pid, size_t size, int protection)
{
    //mmap template:
    //void *mmap (void *__addr, size_t __len, int __prot, int __flags, int __fd, __off_t __offset);

    void* ret = (void*)-1;
#   if defined(ARCH_86)
    ret = inject_syscall(
        pid, 
        //__NR_mmap has been deprecated for 32 bits a long time ago, so we're going to use __NR_mmap2
        __NR_mmap2, //syscall number
        //arguments
        (void*)0, 
        (void*)size, 
        (void*)protection, 
        (void*)(MAP_ANON | MAP_PRIVATE), 
        (void*)-1, 
        (void*)0
    );
#   elif defined(ARCH_64)
    ret = inject_syscall(
        pid, 
        __NR_mmap, //syscall number
        //arguments
        (void*)0, 
        (void*)size, 
        (void*)(uintptr_t)protection, 
        (void*)(MAP_ANON | MAP_PRIVATE), 
        (void*)-1, 
        (void*)0
    );
#   endif

    return ret;
}
```  
  
```c++
void deallocate_memory(pid_t pid, void* src, size_t size)
{
    //munmap template
    //int munmap (void *__addr, size_t __len);
    inject_syscall(pid, __NR_munmap, src, (void*)size, NULL, NULL, NULL, NULL);
}
```  
  
```c++
void* protect_memory(pid_t pid, void* src, size_t size, int protection)
{
    //mprotect template
    //int mprotect (void *__addr, size_t __len, int __prot);
    return inject_syscall(pid, __NR_mprotect, src, (void*)size, (void*)(uintptr_t)protection, NULL, NULL, NULL);
}
```  
  
Example:  
```c++
int main()
{
    pid_t pid = get_process_id("target");
    module_t mod = get_module(pid, "target");
    void* alloc = allocate_memory(pid, 10, PROT_EXEC | PROT_READ | PROT_WRITE);
    std::cout << "Allocated memory: " << alloc << std::endl;
    protect_memory(pid, mod.base, mod.size, PROT_EXEC | PROT_READ | PROT_WRITE);
    return 0;
}
```  
  
Output:  
```
Command Line Path: /proc/6489/cmdline
Command Line: ./target
Current Process Name: target
Process ID found: 6489
Maps file path: /proc/6489/maps
Module path string: /home/rdbo/Documents/Codes/C/linux_gh/target
Module name: target
Base Address: 0x563f6eaf5000
End Address: 0x563f6eafa000
Module Size: 0x5000
Allocated memory: 0x7f8d159a6000
```  
  
Maps file:  
```
563f6eaf5000-563f6eaf8000 rwxp 00000000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
563f6eaf8000-563f6eafa000 rwxp 00002000 08:01 2242313                    /home/rdbo/Documents/Codes/C/linux_gh/target
563f70729000-563f7074a000 rw-p 00000000 00:00 0                          [heap]
...
7f8d1596f000-7f8d15971000 rw-p 00000000 00:00 0 
7f8d159a6000-7f8d159a7000 rwxp 00000000 00:00 0
7f8d159a7000-7f8d159a9000 r--p 00000000 08:01 27793455                   /usr/lib/ld-2.32.so
7f8d159a9000-7f8d159ca000 r-xp 00002000 08:01 27793455                   /usr/lib/ld-2.32.so
7f8d159ca000-7f8d159d3000 r--p 00023000 08:01 27793455                   /usr/lib/ld-2.32.so
7f8d159d3000-7f8d159d4000 r--p 0002b000 08:01 27793455                   /usr/lib/ld-2.32.so
7f8d159d4000-7f8d159d6000 rw-p 0002c000 08:01 27793455                   /usr/lib/ld-2.32.so
```  

# 1.5 - Injecting Shared Libraries  
  
Shared libraries (.so) are the Linux equivalent of Windows DLLs. Let's understand them a bit further:  
. Shared are generally compiled using the flags `-shared` (identifies the output as a shared library) and `-fPIC` (tells the compiler this code can be placed anywhere in the virtual memory, 'position independent code').  
. They can be initialized with a function marked with `__attribute__((constructor))` and uninitialized with `__attribute__((destructor))`. This is not a rule and it is compiler dependent (works on GCC and CLANG, which are the most used compilers on Linux).  
. Once they are injected, we can modify and access the target process memory internally, meaning we don't have to write any fancy functions like in external, just access the memory directly.  
Now, lets understand how we're going to inject the shared library.  
  
On Linux, the C standard library is called `libc` (on most distros), which contains a function called `__libc_dlopen_mode`. This function can be used to load shared libraries, just like `dlopen`, except it does not require `libdl` to be loaded. On some distros, though, `__libc_dlopen_mode` has a different behaviour, so you'd have to make sure it has `libdl` loaded to continue. The first parameter of `__libc_dlopen_mode` and `dlopen` is the library path (which can be either relative or absolute), passed in as a `const char*`. The next parameter is an `int` which lets us specify some flags. For now, we're going to only use the flag `RTLD_LAZY` (check the man page to get to know more).  
  
The parameters of library functions on `x86` are all passed in the stack. On `x64`, the first 6 parameters are passed in registers and the rest goes to the stack:  
```
x64 library call registers:
rdi - arg0
rsi - arg1
rdx - arg2
rcx - arg3
r8  - arg4
r9  - arg5
```  
  
So here's the logic:  
. Load the external 'libc' into the caller process and get the address of the `__libc_dlopen_mode` of the target process.  
. Allocate memory to put the payload and the `path` parameter into the target process.  
. Setup the registers and inject the payload.  
. Restore the original execution.  
. Deallocate the previously allocated memory.  
  
Here's the code of the shared library we're going to inject:  
```c++
#include <stdio.h>
#include <stdlib.h>

void __attribute__((constructor)) lib_entry()
{
    //It prints "Injected!" once the library gets loaded.
    printf("Injected!\n");
}
```  
  
... and the code of the target process:  
```c++
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    while(1)
    {
        printf("Waiting...\n");
        sleep(1);
    }
    return 0;
}
```  
  
Now, let's make a function that does the injection:  
```c++
void load_library(pid_t pid, std::string lib_path)
{
    /* Let's get the address of the 'libc_dlopen_mode' of the target process
     * and store it on 'dlopen_ex' by loading the LIBC of the target process
     * on here and then getting the offset of its own '__libc_dlopen_mode'.
     * Then we sum this offset to the base of the external LIBC module
     */

    module_t libc_ex = get_module(pid, "/libc");

    //Load the external libc on this process
    void* libc_handle = dlopen(libc_ex.path.c_str(), RTLD_LAZY);

    //Get the symbol '__libc_dlopen_mode' from the loaded LIBC module
    void* dlopen_in = dlsym(libc_handle, "__libc_dlopen_mode");

    //Get the loaded libc module information and store it on libc_in
    module_t libc_in = get_module(getpid(), "/libc");

    //Get the offset by subtracting 'libc_in.base' from 'dlopen_in'
    uintptr_t offset = (uintptr_t)dlopen_in - (uintptr_t)libc_in.base;

    //Get the external '__libc_dlopen_mode' by summing the offset to the libc_ex.base
    
    void* dlopen_ex = (void*)((uintptr_t)libc_ex.base + offset);

    //--- Now let's go to the injection part

    int status;
    struct user_regs_struct old_regs, regs;
    unsigned char inj_buf[] =
    {
#       if defined(ARCH_86)
        /* We have to pass the parameters to the stack (in reversed order)
         * The register 'ebx' will store the library path address and the
         * register 'ecx' will store the flag (RTLD_LAZY)
         * After pushing the parameters to the stack, we will call EAX, which
         * will store the address of '__libc_dlopen_mode'
         */
        0x51,       //push ecx
        0x53,       //push ebx
        0xFF, 0xD0, //call eax
        0xCC,       //int3 (SIGTRAP)
#       elif defined(ARCH_64)
        /* On 'x64', we dont have to pass anything to the stack, as we're only
         * using 2 parameters, which will be stored on RDI (library path address) and
         * RSI (flags, in this case RTLD_LAZY).
         * This means we just have to call the __libc_dlopen_mode function, which 
         * will be on RAX.
         */

        0xFF, 0xD0, //call rax
        0xCC,       //int3 (SIGTRAP)
#       endif
    };

    //Let's allocate memory for the payload and the library path
    size_t inj_size = sizeof(inj_buf) + lib_path.size();
    void* inj_addr = allocate_memory(pid, inj_size, PROT_EXEC | PROT_READ | PROT_WRITE);
    void* path_addr = (void*)((uintptr_t)inj_addr + sizeof(inj_buf));

    //Write the memory to our allocated address
    write_memory(pid, inj_addr, inj_buf, sizeof(inj_buf));
    write_memory(pid, path_addr, (void*)lib_path.c_str(), lib_path.size());

    //Attach to the target process
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    wait(&status);

    //Get the current registers to restore later
    ptrace(PTRACE_GETREGS, pid, NULL, &old_regs);
    regs = old_regs;

    //Let's setup the registers according to our payload
#   if defined(ARCH_86)
    regs.eax = (long)dlopen_ex;
    regs.ebx = (long)path_addr;
    regs.ecx = (long)RTLD_LAZY;
    regs.eip = (long)inj_addr; //The execution will continue from 'inj_addr' (EIP)
#   elif defined(ARCH_64)
    regs.rax = (uintptr_t)dlopen_ex;
    regs.rdi = (uintptr_t)path_addr;
    regs.rsi = (uintptr_t)RTLD_LAZY;
    regs.rip = (uintptr_t)inj_addr; //The execution will continue from 'inj_addr' (RIP)
#   endif

    //Inject the modified registers to the target process
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    //Continue the execution
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    //Wait for the int3 (SIGTRAP) breakpoint
    waitpid(pid, &status, WSTOPPED);

    //Set back the old registers
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);

    //Detach from the process and continue the execution
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    //Deallocate the memory we allocated for the injection buffer and the library path
    deallocate_memory(pid, inj_addr, inj_size);
}
```  
  
Example:  
```
int main()
{
    pid_t pid = get_process_id("target");
    std::string lib_path = "/your/path/libtest.so";
    load_library(pid, lib_path);
    return 0;
}
```  
  
Output (from the target program, same in x86 and x64):  
```
Waiting...
...
Waiting...
Waiting...
Waiting...
Waiting...
Injected!
Waiting...
Waiting...
Waiting...
Waiting...
Waiting...
```  

# 2.0 - Shared Libraries (internal)  

Now that we can inject shared libraries on any process we want, we can move on to internal. This part is very, very similar to Windows and does not require much understanding of Linux kernel code. We have used a sample shared library to demonstrate shared library injection, but let's get a bit deeper, starting with function attributes:  
`__attribute__((constructor))` - whatever function that contains this attribute, will be run once the library is loaded.  
`__attribute__((destructor))`  - whatever function that contains this attribute, will be run once the library is **un**loaded.  
The library shares the same virtual memory as the target process, so we can handle everything directly. Also, from previous experiences I had, I noticed that writing C++ directly into the `__attribute__((constructor))` function would make the program crash (in my case). One workaround I did was creating a thread with pthread and running a different function:  
```c++
#include <pthread.h>

void* main_thread(void* args)
{
    //...
}

void __attribute__((constructor)) lib_entry()
{
    printf("Library loaded!\n");
    pthread_t thread;
    pthread_create(&thread, NULL, main_thread, (void*)0);
    //The thread we just created will run once the execution returns
}

void __attribute__((destructor)) lib_exit()
{
    printf("Library unloaded!\n");
}
```

I *think* you can also link the standard C++ library to your shared library and avoiding this workaround, but I couldn't get it working, so that's that.

# 2.1 - Handling process and modules  

When doing things internally, we don't need to handle the process. If you still want to get its PID, you can use `getpid()`. To handle the modules, you could use something called `dl_iterate_phdr`, which will iterate through every loaded module and run a callback function. We're not going to use this method, because it is a bit more complicated and also I had an issue where the base address of the returned module information was wrong. So, let's keep using the same method as the external: parsing the maps file and reading the module information from there.  
Let's write a wrapper function for the external one that doesn't need the 'pid' parameter:  
```c++
module_t get_module_in(std:string mod_name)
{
    //Get the caller process ID through 'getpid()' and then use the external function
    return get_module(getpid(), mod_name);
}
```  
  
# 2.2 - Reading/Writing memory  
  
On internal, reading and writing memory it really straightforward and there are various ways of doing so. Because we're using the same virtual memory as our target process, we can just modify memory using, for example, `memcpy`, or even dereferencing an address and reading or writing to it.  
Reading memory (example 1, recommended):  
```c++
void* address_of_a_buffer = (void*)0xdeadbeef;
int read_buffer;
//memcpy(dst, src, size)
memcpy(&read_buffer, address_of_a_buffer, sizeof(read_buffer));
```

Reading memory (example 2):  
```c++
void* address_of_a_buffer = (void*)0xdeadbeef;
int read_buffer = *(int*)address_of_a_buffer;
```

Writing memory (example 1, recommended):  
```c++
//we just need reverse the parameters from the read memory example
void* address_of_a_buffer = (void*)0xdeadbeef;
int read_buffer = 1337;
//memcpy(dst, src, size)
memcpy(address_of_a_buffer, &read_buffer, sizeof(read_buffer));
//The (4-byte) value of the address 0xdeadbeef is now '1337'.
```  
  
Writing memory (example 2):  
```c++
void* address_of_a_buffer = (void*)0xdeadbeef;
*(int*)address_of_a_buffer = 1337;
//The (4-byte) value of 0xdeadbeef is now '1337'
```  
  
One more thing: to read an address, you have to make sure that page is readable. Same thing for writing to an address, the page it is in has to be writable. If it's not, we can just change it's protection flags.  
  
# 2.3 - Protecting/Allocating/Deallocating Memory  
  
The concept of allocation, deallocating and protecting memory internally is pretty much the same as externally, except we don't have to do any code injection, just directly call the functions.  
  
`mmap` - can be used to allocate memory  
`munmap` - can be used to deallocate memory  
`mprotect` - can be used to change the protection flags of a memory region  
  
To allocate memory, well, we would just call `mmap` as we did before:  
```c++
size_t size = 0x1000; //allocation size
int prot = PROT_EXEC | PROT_READ | PROT_WRITE; //protection flags
mmap(
    NULL, //address
    size, //length
    prot, //protection
    MAP_PRIVATE | MAP_ANON, //flags
    -1, //file descriptor
    0//offset
);
```  
  
To deallocate memory, we just call `munmap` like we did already:  
```c++
size_t size = 0x1000;
void* alloc = mmap(/* ... */);
munmap(
    alloc, //address
    size //length
);
```  
  
And finally, to change the protection flags, we call `mprotect`:  
```c++
/* Attention: the address used in 'mprotect' *has* to be a multiple of the system page size,
 * that's why we're going to make a function especially for it, so that you don't need to do the
 * rounding every time
 */

void protect_memory_in(void* addr, size_t size, int prot)
{
    long pagesize = sysconf(_SC_PAGE_SIZE); //The system page size
    void* src = (void*)((uintptr_t)address & -pagesize); //Making 'addr' a multiple of the system page size
    mprotect(
        src, //address
        size, //length
        protection, //protection
    );
}
```  
  
# 2.4 - Code detouring / hooking  
Detouring or Hooking is a technique used to change the execution flow of a program. Basically, we detour a function and it will go through our custom function, and then we can restore the normal execution. It is the same as on Windows, because it is all x86 instructions at the end of the day. (more coming...)  
