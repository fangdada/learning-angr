# howtouse

&emsp;&emsp;<font size=2>本节我们利用一个简单的Windows下的驱动sys文件来介绍如何利用angr调用其内部函数，我们先来看一个简单的demo：</font></br>

```C
#include <stdio.h>

int retn(int n)
{
	int a=n;
	if(a==2)
		return 'a';
	else
		return 0;

}
int main()
{
	return 0;
}

/*
0000000000400497 <retn>:
  400497:	55                   	push   %rbp
  400498:	48 89 e5             	mov    %rsp,%rbp
  40049b:	89 7d ec             	mov    %edi,-0x14(%rbp)
  40049e:	8b 45 ec             	mov    -0x14(%rbp),%eax
  4004a1:	89 45 fc             	mov    %eax,-0x4(%rbp)
  4004a4:	83 7d fc 02          	cmpl   $0x2,-0x4(%rbp)
  4004a8:	75 07                	jne    4004b1 <retn+0x1a>
  4004aa:	b8 61 00 00 00       	mov    $0x61,%eax
  4004af:	eb 05                	jmp    4004b6 <retn+0x1f>
  4004b1:	b8 00 00 00 00       	mov    $0x0,%eax
  4004b6:	5d                   	pop    %rbp
  4004b7:	c3                   	retq   
*/
```

&emsp;&emsp;<font size=2>以这两种方式进行调用我们的函数都可以成功打印出返回值：</font></br>

```python
 In [1]: cat temp.py
import angr
import claripy

p=angr.Project('./test')

call=p.factory.callable(0x400497)
#call(2)

state=p.factory.blank_state(addr=0x400497)
state.regs.rdi=2
call.set_base_state(state)
call()



In [2]: import angr
   ...: import claripy
   ...: 
   ...: p=angr.Project('./test')
   ...: 
   ...: call=p.factory.callable(0x400497)
   ...: 
   ...: call(2)
   ...: 
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2019-04-12 15:29:09,947 | angr.state_plugins.symbolic_memory | Filling register rbp with 8 unconstrained bytes
Out[2]: <BV64 0x61>

In [3]: state=p.factory.blank_state(addr=0x400497)
   ...: state.regs.rdi=2
   ...: call.set_base_state(state)
   ...: call()
   ...: 
WARNING | 2019-04-12 15:29:17,446 | angr.state_plugins.symbolic_memory | Filling register rbp with 8 unconstrained bytes
Out[3]: <BV64 0x61>

In [4]: 

```

&emsp;&emsp;<font size=2>我发现用`blank_state(addr)`把addr设置到函数内部的话再构造rbp，rsp和栈上的数据的话行不通，会报错无活跃路径，但我转念一想找不到这样做的意义，所以callable还是用来调用完整的函数吧！来看看callable类的实现部分源码：</font></br>

```python
class Callable(object):
    """
    Callable is a representation of a function in the binary that can be
    interacted with like a native python function.

    If you set perform_merge=True (the default), the result will be returned to you, and
    you can get the result state with callable.result_state.

    Otherwise, you can get the resulting simulation manager at callable.result_path_group.
    """

    def __init__(self, project, addr, concrete_only=False, perform_merge=True, base_state=None, toc=None, cc=None):
        """
        :param project:         The project to operate on
        :param addr:            The address of the function to use

        The following parameters are optional:

        :param concrete_only:   Throw an exception if the execution splits into multiple paths
        :param perform_merge:   Merge all result states into one at the end (only relevant if concrete_only=False)
        :param base_state:      The state from which to do these runs
        :param toc:             The address of the table of contents for ppc64
        :param cc:              The SimCC to use for a calling convention
        """
# ...................
# ...................
        
    def set_base_state(self, state):
        """
        Swap out the state you'd like to use to perform the call
        :param state: The state to use to perform the call
        """
        self._base_state = state

    def __call__(self, *args):
        self.perform_call(*args)
        if self.result_state is not None:
            return self.result_state.solver.simplify(self._cc.get_return_val(self.result_state, stack_base=self.result_state.regs.sp - self._cc.STACKARG_SP_DIFF))
        else:
            return None
```

&emsp;&emsp;<font size=2>callable接受addr（我猜无法指定任意地址就是因为必须为函数开头，从压栈保存rbp开始），base_state等，我们可以用set_base_state自定义函数执行前的基本状态。在demo中，我可以直接在call中在arg中传入参数，也可以直接自己手动创建一个状态设置rdi（参数1寄存器）为2，这样都能得到返回值1而不是0。</font></br>

&emsp;&emsp;<font size=2>接下来我们看看正式题目：</font></br>

```C
; BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
_DllMain@12 proc near

hinstDLL= dword ptr  4
fdwReason= dword ptr  8
lpvReserved= dword ptr  0Ch

mov     eax, 1
retn    0Ch
_DllMain@12 endp
```

&emsp;&emsp;<font size=2>main函数什么都没有，但是有一个明显的函数引起我们的注意：</font></br>

```assembly
.text:10001130 ; int __cdecl fnhowtouse(int)
.text:10001130                 public ?fnhowtouse@@YAHH@Z
.text:10001130 ?fnhowtouse@@YAHH@Z proc near           ; DATA XREF: .rdata:off_10002548↓o
.text:10001130
.text:10001130 var_B4          = dword ptr -0B4h
.text:10001130 var_B0          = dword ptr -0B0h
.text:10001130 var_AC          = dword ptr -0ACh
.text:10001130 var_A8          = dword ptr -0A8h
.text:10001130 var_A4          = dword ptr -0A4h
.text:10001130 var_A0          = dword ptr -0A0h
.text:10001130 var_9C          = dword ptr -9Ch
.text:10001130 var_98          = dword ptr -98h
.text:10001130 var_94          = dword ptr -94h
.text:10001130 var_90          = dword ptr -90h
.text:10001130 var_8C          = dword ptr -8Ch
.text:10001130 var_88          = dword ptr -88h
.text:10001130 var_84          = dword ptr -84h
.text:10001130 var_80          = dword ptr -80h
.text:10001130 var_7C          = dword ptr -7Ch
.text:10001130 var_78          = dword ptr -78h
.text:10001130 var_74          = dword ptr -74h
.text:10001130 var_70          = dword ptr -70h
.text:10001130 var_6C          = dword ptr -6Ch
.text:10001130 var_68          = dword ptr -68h
.text:10001130 var_64          = dword ptr -64h
.text:10001130 var_60          = dword ptr -60h
.text:10001130 var_5C          = dword ptr -5Ch
.text:10001130 var_58          = dword ptr -58h
.text:10001130 var_54          = dword ptr -54h
.text:10001130 var_50          = dword ptr -50h
.text:10001130 var_4C          = dword ptr -4Ch
.text:10001130 var_48          = dword ptr -48h
.text:10001130 var_44          = dword ptr -44h
.text:10001130 var_40          = dword ptr -40h
.text:10001130 var_3C          = dword ptr -3Ch
.text:10001130 var_38          = dword ptr -38h
.text:10001130 var_34          = dword ptr -34h
.text:10001130 var_30          = dword ptr -30h
.text:10001130 var_2C          = dword ptr -2Ch
.text:10001130 var_28          = dword ptr -28h
.text:10001130 var_24          = dword ptr -24h
.text:10001130 var_20          = dword ptr -20h
.text:10001130 var_1C          = dword ptr -1Ch
.text:10001130 var_18          = dword ptr -18h
.text:10001130 var_14          = dword ptr -14h
.text:10001130 var_10          = dword ptr -10h
.text:10001130 var_C           = dword ptr -0Ch
.text:10001130 var_8           = dword ptr -8
.text:10001130 var_4           = dword ptr -4
.text:10001130 arg_0           = dword ptr  4
.text:10001130
.text:10001130                 sub     esp, 0B4h
.text:10001136                 mov     eax, offset sub_10001080
.text:1000113B                 mov     [esp+0B4h+var_B4], eax
.text:1000113E                 mov     [esp+0B4h+var_B0], eax
.text:10001142                 mov     eax, offset sub_10001090
.text:10001147                 mov     [esp+0B4h+var_90], eax
.text:1000114B                 mov     [esp+0B4h+var_84], eax
.text:1000114F                 mov     [esp+0B4h+var_80], eax
.text:10001153                 push    esi
.text:10001154                 mov     eax, offset sub_100010A0
.text:10001159                 mov     edx, offset sub_10001030
.text:1000115E                 push    edi
.text:1000115F                 mov     edi, offset sub_100010E0
.text:10001164                 mov     ecx, offset sub_10001100
.text:10001169                 mov     [esp+0BCh+var_7C], eax
.text:1000116D                 mov     [esp+0BCh+var_68], eax
.text:10001171                 mov     eax, offset sub_10001050
.text:10001176                 mov     esi, offset sub_10001040
.text:1000117B                 mov     [esp+0BCh+var_A0], edx
.text:1000117F                 mov     [esp+0BCh+var_8C], edx
.text:10001183                 mov     [esp+0BCh+var_74], edx
.text:10001187                 mov     edx, offset sub_100010F0
.text:1000118C                 mov     [esp+0BCh+var_9C], edi
.text:10001190                 mov     [esp+0BCh+var_6C], edi
.text:10001194                 mov     [esp+0BCh+var_58], edi
.text:10001198                 mov     [esp+0BCh+var_40], eax
.text:1000119C                 mov     [esp+0BCh+var_3C], eax
.text:100011A3                 mov     [esp+0BCh+var_38], edi
.text:100011AA                 mov     [esp+0BCh+var_34], eax
.text:100011B1                 mov     [esp+0BCh+var_24], eax
.text:100011B8                 mov     [esp+0BCh+var_10], eax
.text:100011BF                 mov     eax, [esp+0BCh+arg_0]
.text:100011C6                 mov     [esp+0BCh+var_98], esi
.text:100011CA                 mov     [esp+0BCh+var_54], esi
.text:100011CE                 mov     [esp+0BCh+var_48], esi
.text:100011D2                 mov     [esp+0BCh+var_C], esi
.text:100011D9                 pop     edi
.text:100011DA                 mov     [esp+0B8h+var_AC], offset sub_10001070
.text:100011E2                 mov     [esp+0B8h+var_A8], offset sub_10001110
.text:100011EA                 mov     [esp+0B8h+var_A4], offset sub_10001060
.text:100011F2                 mov     [esp+0B8h+var_94], ecx
.text:100011F6                 mov     [esp+0B8h+var_88], offset sub_10001010
.text:100011FE                 mov     [esp+0B8h+var_78], offset sub_10001060
.text:10001206                 mov     [esp+0B8h+var_70], edx
.text:1000120A                 mov     [esp+0B8h+var_64], offset sub_100010B0
.text:10001212                 mov     [esp+0B8h+var_60], offset sub_100010D0
.text:1000121A                 mov     [esp+0B8h+var_5C], ecx
.text:1000121E                 mov     [esp+0B8h+var_50], edx
.text:10001222                 mov     [esp+0B8h+var_4C], edx
.text:10001226                 mov     [esp+0B8h+var_44], ecx
.text:1000122A                 mov     [esp+0B8h+var_30], offset sub_10001060
.text:10001235                 mov     [esp+0B8h+var_2C], offset sub_10001010
.text:10001240                 mov     [esp+0B8h+var_28], ecx
.text:10001247                 mov     [esp+0B8h+var_20], ecx
.text:1000124E                 mov     [esp+0B8h+var_1C], offset sub_10001020
.text:10001259                 mov     [esp+0B8h+var_18], offset sub_100010C0
.text:10001264                 mov     [esp+0B8h+var_14], offset sub_100010B0
.text:1000126F                 mov     [esp+0B8h+var_8], edx
.text:10001276                 mov     [esp+0B8h+var_4], offset sub_10001120
.text:10001281                 mov     ecx, [esp+eax*4+0B8h+var_B4]
.text:10001285                 pop     esi
.text:10001286                 add     esp, 0B4h
.text:1000128C                 jmp     ecx
.text:1000128C ?fnhowtouse@@YAHH@Z endp
```

&emsp;&emsp;<font size=2>分析逻辑可以得到，把一大堆函数地址存到了栈里面然后从栈的底部+4*参数的偏移开始调用函数，每个函数都只返回一个字节，猜测这些字节就是flag：</font></br>

```assembly
.text:10001010 sub_10001010    proc near               ; DATA XREF: fnhowtouse(int)+C6↓o
.text:10001010                                         ; fnhowtouse(int)+105↓o
.text:10001010                 mov     eax, 61h
.text:10001015                 retn
.text:10001015 sub_10001010    endp
.text:10001015
.text:10001015 ; ---------------------------------------------------------------------------
.text:10001016                 align 10h
.text:10001020
.text:10001020 ; =============== S U B R O U T I N E =======================================
.text:10001020
.text:10001020
.text:10001020 sub_10001020    proc near               ; DATA XREF: fnhowtouse(int)+11E↓o
.text:10001020                 mov     eax, 62h
.text:10001025                 retn
.text:10001025 sub_10001020    endp
.text:10001025
.text:10001025 ; ---------------------------------------------------------------------------
.text:10001026                 align 10h
.text:10001030
.text:10001030 ; =============== S U B R O U T I N E =======================================
.text:10001030
.text:10001030
.text:10001030 sub_10001030    proc near               ; DATA XREF: fnhowtouse(int)+29↓o
.text:10001030                 mov     eax, 63h
.text:10001035                 retn
.text:10001035 sub_10001030    endp
```

&emsp;&emsp;<font size=2>这题目的常规解应该就是调用LoadLibrary然后使用GetProcAddress获取地址然后迭代调用收集flag就行了，用angr我们可以更快更简单的完成：只需要直接使用callable就可以实现！</font></br>

&emsp;&emsp;<font size=2>所以完整脚本如下：</font></br>

```python
#!/usr/bin/env python

#
# This binary, from the MMA CTF, was a simple reversing challenge. THe biggest
# challenge was actually *running* this library in Windows. Luckily, with angr,
# we can avoid having to do this!
#
# The approach here is to use angr as a concrete execution engine to call the
# `howtouse` function 45 times, as the array of function pointers in that
# function has 45 entries. The result turned out to be the flag.
#

import angr
import claripy

def main():
    # Load the binary. Base addresses are weird when loading binaries directly, so
    # we specify it explicitly.
    p = angr.Project('howtouse.dll', load_options={'main_opts': {'base_addr': 0x10000000}})

    # A "Callable" is angr's FFI-equivalent. It allows you to call binary functions
    # from Python. Here, we use it to call the `howtouse` function.
    howtouse = p.factory.callable(0x10001130)

    # In this binary, the result is a concrete char, so we don't need a symbolic
    # state or a solver to get its value.
    getch = lambda i: chr(claripy.backends.concrete.convert(howtouse(i)).value)

    # Let's call this 45 times, and that's the result!
    return ''.join(getch(i) for i in range(45))

def test():
    assert main() == 'MMA{fc7d90ca001fc8712497d88d9ee7efa9e9b32ed8}'

if __name__ == '__main__':
    print(main())
```

