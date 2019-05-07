# Android ELF编写与调试环境搭建

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这破环境我搭了两天才搭好，遇到了不少坑，所以特开一篇文章记录，虽然我的环境是Mac OS X但是其实差不多，总结下来就是这几步：</font></br>

- 安装Android Studio；
- 在Android Studio里面用AVD manager开一个虚拟安卓设备；
- 安装NDK并生成android-build；
- 使用arm-linux-androideabi-gcc生成arm ELF二进制程序；
- 使用adb（Android Debug Bridge）运行Android shell；
- 使用adb push把程序放入虚拟机；
- 运行之并掌握remote debug。

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么以上就是我要在这篇文章里面讲解的内容了。我们一步一步来：</font></br>

## 1. 安装Android Studio

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>Android studio是谷歌官方的IDE，其功能特别强大，官方下载地址：<https://developer.android.com/studio>，因为Android SDK也已经集成在里面了，安装过程也十分简单，故不赘述（如果先前自己已经安装了Android SDK的话就要指定一下自己安装的目录）。</font></br>

## 2. 使用AVD manager创建虚拟安卓设备

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>打开Android studio，直接在开始界面上点击Configure->AVD Manager：</font></br>

![AVD_Manager](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/AVD_Manager.png>)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（忽视壁纸2333每天随机换的）然后点击**create virtual device后选择一个不带Play Store**（别问，问就是会出现**unauthorized**的问题），如下：</font></br>

![create_virtual_device](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/create_virtual_device.png>)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后点击next，注意因为我们是要搭建arm指令集的环境，所以**不要用recommend和x86里面的系统镜像，选择other images**，然后我选了第一个ABI为arm64-v8a的Android7.1.1的（点击release name旁边的下载先下载），点击next后直接finish就行了。</font></br>

![system_image](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/system_image.png>)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完了之后点一下AVD manager里的action里的绿色开始键就行了，你就能看到一个模拟的安卓手机在你屏幕上2333。这时候可能会有框跳出来建议安装x86的镜像，无视就行（**我们要arm！！！**）。</font></br>

## 3. 安装NDK并生成Android-build

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>Android NDK是一套可以让你使用C和C++等语言，以原生代码实现部分应用的工具集。去官网下载NDK：<https://developer.android.com/ndk/downloads>。选择你自己系统版本的压缩包下载下来解压就好，然后在android-ndk-r18b/build/tools/目录下，用`./make_standalone_toolchain.py --arch arm --api 28 --install-dir ~/Desktop/file/android-build`，说明一下上面的代码。使用py而不用sh是因为sh将被舍弃，--arch就是要生成的工具集的目标架构，这里我们用arm，--api就是Google api，对应你选择的系统镜像的API版本就行了，--install-dir就是安装的目录，是未被创建的目录，不是已存在的，自己选个就好。</font></br>

## 4. 使用arm-linux-androideabi-gcc生成arm ELF二进制程序

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完了之后在你指定的目录下会有一个android-build文件夹，android-build/bin/下就有我们要的编译工具：arm-linux-androideabi-gcc，用他就可以生成我们想要的arm指令集的ELF程序，在这里为了方便我把它加入了alias：`alias arm-gcc="/user/******/android-build/bin/arm-linux-androideabi-gcc"。`</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后写个hello world：</font></br>

```C
#include <stdio.h>

int main()
{
	printf("hello,world\n");

	return 0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>使用编译命令：`arm-gcc test.c -pie -fPIE -o test`。然后就生成了一个我们期望的二进制程序了：</font></br>

```shell
➜  android-elf arm-gcc -pie -fPIE test.c -o test
➜  android-elf file test
test: ELF 32-bit LSB pie executable ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /system/bin/linker, not stripped
➜  android-elf
```

## 5. 使用adb运行shell并把二进制程序推送到设备

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>adb就在Android SDK里面，一般已经随Android Studio一起安装了，我的目录是：/Users/fanda/Library/Android/sdk/platform-tools，然后我用export PATH=/Users/fanda/Library/Android/sdk/platform-tools:$PATH把它添加进了环境变量，接下来就可以直接使用adb命令了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>（在虚拟安卓设备启动的情况下）使用adb devices会看到类似如下：</font></br>

```shell
➜  platform-tools adb devices
List of devices attached
emulator-5554	device

➜  platform-tools
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>如果是unauthorized的确认下自己是不是下了带Google play版本的，这时候再使用`adb shell`就可以进入虚拟安卓设备的shell了，建议直接`adb shell`之前先`adb root`用root登录。</font></br>

```shell
➜  platform-tools adb root
restarting adbd as root
➜  platform-tools adb shell
generic_arm64:/ # ls
acct       data              fstab.ranchu-encrypt   init.ranchu-noencrypt.rc init.zygote64_32.rc sbin             storage             var
bugreports default.prop      fstab.ranchu-noencrypt init.ranchu.rc           mnt                 sdcard           sys                 vendor
cache      dev               init                   init.rc                  oem                 seapp_contexts   system
charger    etc               init.environ.rc        init.usb.configfs.rc     proc                selinux_version  ueventd.goldfish.rc
config     file_contexts.bin init.goldfish.rc       init.usb.rc              property_contexts   sepolicy         ueventd.ranchu.rc
d          fstab.goldfish    init.ranchu-encrypt.rc init.zygote32.rc         root                service_contexts ueventd.rc
generic_arm64:/ #
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在推送前还有一件事要做，那就是确保推送的目录是rw（可读可写）的，使用`cat /proc/mounts`命令查看（我已经remount过了所以都是可读可写）：</font></br>

```shell
generic_arm64:/ # cat /proc/mounts
rootfs / rootfs ro,seclabel,relatime 0 0
tmpfs /dev tmpfs rw,seclabel,nosuid,relatime,mode=755 0 0
devpts /dev/pts devpts rw,seclabel,relatime,mode=600 0 0
proc /proc proc rw,relatime,gid=3009,hidepid=2 0 0
sysfs /sys sysfs rw,seclabel,relatime 0 0
selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0
debugfs /sys/kernel/debug debugfs rw,seclabel,relatime,mode=755 0 0
none /acct cgroup rw,relatime,cpuacct 0 0
tmpfs /mnt tmpfs rw,seclabel,relatime,mode=755,gid=1000 0 0
none /dev/cpuctl cgroup rw,relatime,cpu 0 0
/dev/block/vda /system ext4 ro,seclabel,relatime,data=ordered 0 0
/dev/block/vdb /cache ext4 rw,seclabel,nosuid,nodev,noatime,errors=panic,data=ordered 0 0
/dev/block/vdc /data ext4 rw,seclabel,nosuid,nodev,noatime,errors=panic,data=ordered 0 0
tmpfs /storage tmpfs rw,seclabel,relatime,mode=755,gid=1000 0 0
/dev/block/vdc /data/var/run/netns ext4 rw,seclabel,nosuid,nodev,noatime,errors=panic,data=ordered 0 0
proc net:[4026533148] proc rw,relatime,gid=3009,hidepid=2 0 0
proc net:[4026533148] proc rw,relatime,gid=3009,hidepid=2 0 0
generic_arm64:/ #
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>比如我要修改/data文件夹的读写权限（这不是chmod可以解决的），使用如下命令：`mount -o remount,rw -t ext4 /dev/block/vdc /data`。其中后面因人而异的格式为：-t <磁盘格式> block名称 文件夹名称，我的环境里格式为ext4，而且/data文件夹挂载在了/dev/block/vdc上所以用了上述命令。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>完了之后`adb remount`一下，然后用`adb push [filename] [dir] `，就行了，[filename]就是你要推送的文件，[dir]就是推送的目的路径（虚拟设备的）。我在这里用`adb push test /data/temp`放在了我自行创建的temp目录下，然后就可以执行了：</font></br>

```shell
➜  android-elf ls
solve.py test     test.c   validate
➜  android-elf adb push test /data/temp
test: 1 file pushed. 0.1 MB/s (6740 bytes in 0.094s)
➜  android-elf adb shell
generic_arm64:/ # cd data/temp
generic_arm64:/data/temp # ./test
hello,world
generic_arm64:/data/temp #
```

## 6. remote debug（gdb和IDA）

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么程序我们已经有了，如何调试呢？有两个办法：一个是把gdb传过去直接在虚拟机shell里调试；一个是远程用宿主机调试。前一个不讲了，不讲也会，这里就讲后一个方法吧。</font></br>

### 首先GDB remote debug：

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其实我们的虚拟安卓设备的shell已经自带了gdbserver，我们只需要用adb的forward选项设置一下套接字转发就跟常规的远程调试差不多了：`adb forward tcp:1234 tcp:1234`。随后如下使用gdbserver挂载程序等待监听： </font></br>

```shell
➜  android-elf adb forward tcp:1234 tcp:1234
1234
➜  android-elf adb shell
generic_arm64:/ # cd data/temp
generic_arm64:/data/temp # ls
android_server test validate
generic_arm64:/data/temp # gdbs
gdbserver    gdbserver64
generic_arm64:/data/temp # gdbserver :1234 ./test
Process ./test created; pid = 7580
Listening on port 1234

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>回到我们的宿主机，在我们之前生成的Android-build/bin/目录下的gdb直接用`remote target:1234`就行了，效果如下：</font></br>

```shell
➜  bin pwd
/Users/fanda/Desktop/file/android-build/bin
➜  bin ./gdb
GNU gdb (GDB) 7.11
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-apple-darwin14.5.0".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
gdb-peda$ target remote:1234
Remote debugging using :1234
Reading /data/temp/test from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /data/temp/test from remote target...
Reading symbols from target:/data/temp/test...(no debugging symbols found)...done.
Reading /system/bin/linker from remote target...
Reading /system/bin/linker from remote target...
Reading symbols from target:/system/bin/linker...Reading /system/bin/.debug/linker from remote target...
(no debugging symbols found)...done.
Warning: not running or target is remote
0xf778c784 in __dl__start () from target:/system/bin/linker
gdb-peda$
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后gdb用命令`b main`再`c`，打印指令`x/10i $pc`就可以看到我们的main函数了：</font></br>

```shell
gdb-peda$ b main
Breakpoint 1 at 0xaab84470
gdb-peda$ c
Continuing.
Reading /system/lib/libc.so from remote target...
Reading /system/lib/.debug/libc.so from remote target...
Reading /system/lib/libnetd_client.so from remote target...
Reading /system/lib/.debug/libnetd_client.so from remote target...
Reading /system/lib/libc++.so from remote target...
Reading /system/lib/.debug/libc++.so from remote target...
Reading /system/lib/libm.so from remote target...
Reading /system/lib/.debug/libm.so from remote target...
gdb-peda$ x/10i $pc
=> 0xaab84470 <main+12>:	ldr	r0, [pc, #32]	; 0xaab84498 <main+52>
   0xaab84474 <main+16>:	add	r0, pc, r0
   0xaab84478 <main+20>:	movw	r1, #0
   0xaab8447c <main+24>:	str	r1, [sp, #4]
   0xaab84480 <main+28>:	bl	0xaab843c0 <printf@plt>
   0xaab84484 <main+32>:	movw	r1, #0
   0xaab84488 <main+36>:	str	r0, [sp]
   0xaab8448c <main+40>:	mov	r0, r1
   0xaab84490 <main+44>:	mov	sp, r11
   0xaab84494 <main+48>:	pop	{r11, pc}
gdb-peda$
```

### IDA remote debug

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这个比较简单，用`adb push`命令把IDA的android_server传送过去（别跟我说这个是啥），然后`adb forward tcp:23946 tcp:23946`，转发一下端口（23946是IDA远程调试端口）后，直接运行android-server就行了：</font></br>

```shell
➜  bin adb forward tcp:23946 tcp:23946
23946
➜  bin adb shell
generic_arm64:/ # cd data/temp
generic_arm64:/data/temp # ./android_server
IDA Android 32-bit remote debug server(ST) v1.22. Hex-Rays (c) 2004-2017
Listening on 0.0.0.0:23946...


```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>然后打开IDA，选择**Debugger->run->Remote ARMLinux/Android debugger**，因为我直接把Android_server放在了test同目录里，所以直接像下面这样写就行了：</font></br>

![create_IDA_remote](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/create_IDA_remote.png>)

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>点击ok直接来到了\_\_dl\_\_start处，F8跳过若干次，根据IDA里的start处，main函数被保存在如图R2里，单步运行到此处，右键R2寄存器，jump到这个地址后按C分析代码后就是main函数的代码了，F2下断后运行一次就断在了main函数开头。IDA remote debug就是这样了：</font></br>

![dynamic_libc_init](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/dynamic_libc_init.png>)

![libc_init](<https://raw.githubusercontent.com/fangdada/ctf/master/screenshot/arm-environment/libc_init.png>)

![dynamic_main](<https://github.com/fangdada/ctf/blob/master/screenshot/arm-environment/dynamic_main.png>)

