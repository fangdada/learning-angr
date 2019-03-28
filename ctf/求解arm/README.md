# android_arm_license_validation

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这次就来讲讲arm题吧，这题是Android arm（32位）下的一题base32题，要求输入一串正确的base32值，然后被程序decode之后比较是否正确。有IDA在其实也用不着很精通arm指令集，得亏了强大的F5。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>因为我懒得再去写常规解了，所以直接只写这一个angr解，环境搭建过程另写了一篇文章：[Android ELF编写与调试环境搭建](https://github.com/fangdada/learning-angr/blob/master/ctf/%E6%B1%82%E8%A7%A3arm/build_envir.md)，里面总结了我摸索得到的经验和一些坑。IDA打开之后直接来到main函数一个F5:</font></br>

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char **v4; // [sp+8h] [bp-24h]
  int v5; // [sp+14h] [bp-18h]
  char v6; // [sp+18h] [bp-14h]

  v4 = argv;
  if ( argc != 2 )
    puts_usage();
  if ( strlen(argv[1]) != 16 )
    return_error();
  puts("Entering base32_decode");
  b32decode(0, v4[1], 0x10u, (int)&v6, &v5);
  printf("Outlen = %d\n", v5);
  puts("Entering check_license");
  verify(&v6);
  return 0;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>几个自定义函数我已经重命名了，逻辑非常简单，输入一个长度为16字节的base32 encode串，经过b32decode这个正宗的base32解码函数解码出来的字符串到verify里比较是否等于"\x00L\x00O\x00L\x00Z\x00!"，伪代码如下：</font></br>

```C
unsigned int flag[]={
  'L','O','L','Z','!'
};
output=b32deocde(input);
if(output[0]==flag[0] && \
   output[1]==flag[1] && \
   output[2]==flag[2] && \
   output[3]==flag[3] && \
   output[4]==flag[4]
)
    put_success();
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其实这题因为太过简单直接分析verify函数，然后python就能解了：</font></br>

```shell
In [1]: flag=b'\x00L\x00O\x00L\x00Z\x00!'

In [2]: import base64

In [3]: base64.b32encode(flag)
Out[3]: b'ABGAATYAJQAFUABB'

In [4]: exit
➜  android_arm_license_validation git:(master) adb shell
generic_arm64:/ # cd data/temp
generic_arm64:/data/temp # ./validate ABGAATYAJQAFUABB
Entering base32_decode
Outlen = 10
Entering check_license
Product activation passed. Congratulations!
generic_arm64:/data/temp #
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>2333但是既然我们是来学angr的，所以我们就用如何用angr求解的方式思考一下。众所周知base32加解码的时候是要用到映射表的，这在符号执行里行不通（试想一下，一个符号去置换一个表中的元素，到底该换成哪一个？），所以直接用angr求解会卡住，但是既然base32算法已知为何不直接跳过呢？</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>所以我们要直接从verify函数下手，求解正确的base32decode之后的输入，然后再把结果base32encode一下就是flag了。有了思路后，我们实际的操作就是：</font></br>

- 用blank_state()直接加载verify函数开始之前的状态；
- 设置参数为符号变量；
- 求解结果，完事。

```python
import angr
import claripy
import base64

load_options = {}
# Android NDK library path:
# load_options['ld_path'] = ['/Users/berndt/Tools/android-ndk-r10e/platforms/android-21/arch-arm/usr/lib']

# 加载题目到调用verify函数前
b = angr.Project("./validate", load_options = load_options)
state = b.factory.blank_state(addr=0x401760)

# 设置参数为符号变量
# arm中r0-r3为参数，类似rdi,rsi,rdx
concrete_addr = 0xffe00000
code = claripy.BVS('code', 10*8)
state.memory.store(concrete_addr, code, endness='Iend_BE')
state.regs.r0 = concrete_addr

sm = b.factory.simulation_manager(state)
sm.explore(find=0x401840, avoid=0x401854)
found = sm.found[0]

# 求解的结果其实就是'\x00L\x00O\x00L\x00Z\x00!'
solution = found.solver.eval(code, cast_to=bytes)
print(base64.b32encode(solution))
```

