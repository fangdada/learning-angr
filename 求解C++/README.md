# csaw_wyvern

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这一节我们来学习如何用angr应对C++程序，angr自己只实现了一些常用的C函数，而没有C++函数，所以在遇到C++的题时用常规的做法是非常耗时间的（因为angr需要一直执行C++的库函数直到遇到C++库函数底层调用的C函数部分）。在进入正题之前我们先来看一个demo：</font></br>

```C
#include <iostream>

int main()
{
	using namespace std;
	int a;
	int b;

	cout<<"hello"<<endl;

	cin>>a;
	cout<<"get your input!"<<endl;	//在此处测试angr执行C++库函数的速度
	if(a==2)
		cout<<"good"<<endl;
	else
		cout<<"failed"<<endl;

	return 0;
}

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这是一个非常简单的C++程序，接受单个输入，然后判断是否为2。按照我以前的做法，肯定是直接在if前生成blank_state瞬间就可以破了这个demo，但是我们要检验一下angr执行C++库函数的效率，所以我们先用以下脚本尝试执行看需要耗费多少时间：</font></br>

```python
import angr
import claripy
import time

start=0x4008c1
end=0x4008fe
avoid=0x400932

before=time.time()
p=angr.Project('./test')
state=p.factory.blank_state(addr=start)

state.regs.rbp=state.regs.rsp
state.regs.rsp=state.regs.rsp-0x40
state.mem[state.regs.rbp-0x8].int=claripy.BVS("flag1",32,explicit_name=True)

sm=p.factory.simulation_manager(state)
sm.explore(find=end,avoid=avoid)
after=time.time()

print("cost:"+str(after-before))
found=sm.found[0]
print(found.solver.eval(claripy.BVS("flag1",32,explicit_name=True),cast_to=int))

'''
balabalabalabala.......lots of warnings!
........................................
WARNING | 2019-04-08 19:25:59,203 | angr.state_plugins.symbolic_memory | Filling memory at 0xffffffffffffffd6 with 8 unconstrained bytes
WARNING | 2019-04-08 19:25:59,343 | angr.state_plugins.symbolic_memory | Filling memory at 0xfe00000000000060 with 8 unconstrained bytes
WARNING | 2019-04-08 19:25:59,619 | angr.engines.successors | Exit state has over 256 possible solutions. Likely unconstrained; skipping. <BV64 mem_fe00000000000060_155_64{UNINITIALIZED}>
cost:31.564738273620605
2
'''
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>程序生成了大量的warning，光一个cout输出一个字符串和一个换行符就执行了超过30s！这要是C实现的秒解好吧。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么什么是angr解C++的正确做法呢？首先我们需要用`full_init_state()`来初始化程序，而不是用`blank_state()`，否则angr在执行程序的时候会花相当多的时间耗费在C++库函数的探索上。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们改一下代码改成如下所示，使用`full_init_state()`初始化程序，然后使用run方法探索：</font></br>

```python
import angr
import claripy
import time

before=time.time()
p=angr.Project('./test')
flag=claripy.BVS("flag",8,explicit_name=True)
state=p.factory.full_init_state(args=['./test'],stdin=flag)

sm=p.factory.simulation_manager(state)
sm.run()
after=time.time()
print("cost:"+str(after-before))
# cost:74.04902362823486
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>额，时间怎么要这么久？因为`full_init_state()`会加载所有的库然后到装载器的一个空间里执行一些类似初始化操作，然后再跑到入口处开始执行，形象一点的话代码如下：</font></br>

```python
import angr
import time

p=angr.Project('./test')

state=p.factory.full_init_state()
sm=p.factory.successors(state,num_inst=1)
sm=sm.successors[0]

before=time.time()
while sm.addr!=0x400870:
    sm=p.factory.successors(sm,num_inst=1)
    sm=sm.successors[0]
after=time.time()

print("step to main cost:"+str(after-before))
# step to main cost:113.31757998466492

before=time.time()
sm=p.factory.simulation_manager(sm)
sm.explore(find=0x4008aa) # 从main开头执行完第一个cout<<"hello"<<endl;函数
after=time.time()

print("cout<<strings<<end cost:"+str(after-before))
# cout<<strings<<end cost:1.9847142696380615
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>与第一个`blank_state()`相比，不算初始化的话，差距达到了近**16:1**！所以如果是比较大型的二进制程序的话，建议用`full_init_state()`装载执行。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么还有没有再次提升的办法呢？有！用unicorn引擎进行装载执行。将之前直接用run方法的代码加上一个`add_options=angr.options.unicorn`就行了，看看时间消耗：</font></br>

```python
import angr
import claripy
import time

before=time.time()
p=angr.Project('./test')
flag=claripy.BVS("flag",8,explicit_name=True)
state=p.factory.full_init_state(args=['./test'],add_options=angr.options.unicorn
,stdin=flag)

sm=p.factory.simulation_manager(state)
sm.run()
after=time.time()
print("cost:"+str(after-before))
# cost:17.34348964691162

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>非常可观的时间优化，执行完所有的路径探索甚至比`blank_state()`光光执行两个cout还要快，所以一般遇到这类C++写的二进制程序时应当使用angr的unicorn引擎加载，执行指令非常快，只不过缺点可能就是无法像`blank_state()`那样指定一段地址执行了。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这里插一个题外话，要再次提速可以试试用pypy，把python转为JIT执行，会进一步缩小脚本执行时间（后来我笔记本快没电了2333，实际上正式题目中pypy可以缩小很多时间耗费，不信看下面的正式题目），搭建这个只需要几步即可：</font></br>

```shell
wget https://bitbucket.org/pypy/pypy/downloads/pypy3.6-v7.1.0-linux64.tar.bz2
tar -xvf pypy3.6-v7.1.0-linux64.tar.bz2
# 可以直接设置pypy的bin目录进入环境变量，就可以直接通过pypy3使用了
wget https://bootstrap.pypa.io/get-pip.py
pypy3 get-pip.py
pypy3 -m pip install angr
# 然后就可以正常使用了，相当于pypy3来替代python3
<pypy3 your_scripy.py>
# 例如
➜  test pypy3 c++.py
cost:17.257989168167114
```

***

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>在上面扯完了C++在angr中的不同之处和优化后，我们正式来看看这道题目：</font></br>

**main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST24_4
  __int64 v4; // rdx
  char v6; // [rsp+80h] [rbp-140h]
  char v7; // [rsp+88h] [rbp-138h]
  char v8; // [rsp+A0h] [rbp-120h]
  char v9; // [rsp+A8h] [rbp-118h]
  char s; // [rsp+B0h] [rbp-110h]
  int v11; // [rsp+1BCh] [rbp-4h]

  v11 = 0;
  std::operator<<<std::char_traits<char>>(&std::cout, (unsigned int)"+-----------------------+\n", envp);
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"|    Welcome Hero       |\n",
    "|    Welcome Hero       |\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"+-----------------------+\n\n",
    "+-----------------------+\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"[!] Quest: there is a dragon prowling the domain.\n",
    "[!] Quest: there is a dragon prowling the domain.\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"\tbrute strength and magic is our only hope. Test your skill.\n\n",
    "\tbrute strength and magic is our only hope. Test your skill.\n\n");
  std::operator<<<std::char_traits<char>>(
    &std::cout,
    (unsigned int)"Enter the dragon's secret: ",
    "Enter the dragon's secret: ");
  fgets(&s, 257, stdin);
  std::allocator<char>::allocator(&v8, 257LL);
  std::string::string(&v9, &s, &v8);
  std::allocator<char>::~allocator(&v8);
  std::string::string((std::string *)&v7, (const std::string *)&v9);
  v3 = start_quest((std::string *)&v7);
  std::string::~string((std::string *)&v7);
  if ( v3 == 4919 )
  {
    std::string::string((std::string *)&v6, (const std::string *)&v9);
    reward_strength(&v6, &v9);
    std::string::~string((std::string *)&v6);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(
      &std::cout,
      (unsigned int)"\n[-] You have failed. The dragon's power, speed and intelligence was greater.\n",
      v4);
  }
  v11 = 0;
  std::string::~string((std::string *)&v9);
  return v11;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其中对输入加密有关的函数是`start_quest()`，这个函数经过大量混淆，拿头逆是不可能的，肯定要借助某些工具或者方法，那么用angr我们就可以很简单的探索出我们需要的预期解，也就是输出"success"。</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>整个程序除了混淆的函数比较复杂之外，没有什么angr需要特别绕过的地方（比如置换表或者计数等会路径爆炸的东西，这都是angr的天敌），所以只需要用类似之前的办法，利用一个stdin传入符号变量就能约束求解了，完整脚本如下：</font></br>

```python
#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

def main():
    # Load the binary. This is a 64-bit C++ binary, pretty heavily obfuscated.
    # its correct emulation by angr depends heavily on the libraries it is loaded with,
    # so if this script fails, try copying to this dir the .so files from our binaries repo:
    # https://github.com/angr/binaries/tree/master/tests/x86_64
    p = angr.Project('wyvern')

    # It's reasonably easy to tell from looking at the program in IDA that the key will
    # be 29 bytes long, and the last byte is a newline. Let's construct a value of several
    # symbols that we can add constraints on once we have a state.

    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(28)]
    flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])

    # This block constructs the initial program state for analysis.
    # Because we're going to have to step deep into the C++ standard libraries
    # for this to work, we need to run everyone's initializers. The full_init_state
    # will do that. In order to do this peformantly, we will use the unicorn engine!
    st = p.factory.full_init_state(
            args=['./wyvern'],
            add_options=angr.options.unicorn,
            stdin=flag,
    )

    # Constrain the first 28 bytes to be non-null and non-newline:
    for k in flag_chars:
        st.solver.add(k != 0)
        st.solver.add(k != 10)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.run()

    # Get the stdout of every path that reached an exit syscall. The flag should be in one of these!
    out = b''
    for pp in sm.deadended:
        out = pp.posix.dumps(1)
        if b'flag{' in out:
            return next(filter(lambda s: b'flag{' in s, out.split()))

    # Runs in about 15 minutes!

def test():
    assert main() == b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>我们看看pypy3和python3跑这个脚本的时间消耗：</font></br>

```shell
➜  csaw_wyvern git:(master) python3 solve.py
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-04-09 10:00:03,175 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-04-09 10:00:03,176 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff00 with 8 unconstrained bytes
WARNING | 2019-04-09 10:00:03,544 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012b38 with 29 unconstrained bytes
WARNING | 2019-04-09 10:00:07,612 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012c6a with 29 unconstrained bytes
WARNING | 2019-04-09 10:03:06,081 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00133f4 with 28 unconstrained bytes
WARNING | 2019-04-09 10:03:06,574 | angr.state_plugins.symbolic_memory | Filling memory at 0xc001344f with 27 unconstrained bytes
WARNING | 2019-04-09 10:03:07,001 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0013483 with 65 unconstrained bytes
b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'
Time elapsed: 195.80076503753662
```

```shell
➜  csaw_wyvern git:(master) pypy3 solve.py 
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-04-09 00:50:54,196 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-04-09 00:50:54,197 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-04-09 00:50:54,197 | angr.state_plugins.symbolic_memory | Filling memory at 0x7fffffffffeff00 with 8 unconstrained bytes referenced from 0x409dc70 (strlen+0x0 in libc.so.6 (0x9dc70))
WARNING | 2019-04-09 00:50:55,275 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012b38 with 29 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:50:59,297 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0012c6a with 29 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:07,921 | angr.state_plugins.symbolic_memory | Filling memory at 0xc00133f4 with 28 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:08,402 | angr.state_plugins.symbolic_memory | Filling memory at 0xc001344f with 27 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
WARNING | 2019-04-09 00:52:08,985 | angr.state_plugins.heap.heap_base | Allocation request of 155 bytes exceeded maximum of 128 bytes; allocating 155 bytes
WARNING | 2019-04-09 00:52:09,064 | angr.state_plugins.symbolic_memory | Filling memory at 0xc0013483 with 65 unconstrained bytes referenced from 0x40bb460 (memcpy+0x0 in libc.so.6 (0xbb460))
b'flag{dr4g0n_or_p4tric1an_it5_LLVM}'
Time elapsed: 92.14751529693604
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>综上，遇到C++程序优化方法可以如下：</font></br>

- 使用`full_init_state(add_options=angr.options.unicorn)`装载程序；
- 使用pypy运行脚本