# ais3_crackme

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这次咱们学学命令行输入下怎么用angr做一些简单的crackme，话不多说，看看IDA伪代码：</font></br>

**main**

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax

  if ( argc == 2 )
  {
    if ( (unsigned int)verify((__int64)argv[1]) )
      puts("Correct! that is the secret key!");
    else
      puts("I'm sorry, that's the wrong secret key!");
    result = 0;
  }
  else
  {
    puts("You need to enter the secret key!");
    result = -1;
  }
  return result;
}
```

**verify**

```C
_BOOL8 __fastcall verify(__int64 a1)
{
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; *(_BYTE *)(i + a1); ++i )
  {
    if ( encrypted[i] != ((unsigned __int8)((unsigned __int8)(*(_BYTE *)(i + a1) ^ i) << ((i ^ 9) & 3)) | (unsigned __int8)((signed int)(unsigned __int8)(*(_BYTE *)(i + a1) ^ i) >> (8 - ((i ^ 9) & 3))))
                       + 8 )
      return 0LL;
  }
  return i == 23;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>其中的encrypted就是一个密文表，可以看到加密对比要求逆还是要花些功夫的，但是用angr可以很轻（wu）松（nao）的完成，构造命令行输入的话就要用到另一个库叫claripy，其他的都差不多：</font></br>

```python
import angr
import claripy

project = angr.Project("./ais3_crackme")
argv1 = claripy.BVS("argv1",100*8) #since we do not the length now, we just put 100 byte

initial_state = project.factory.entry_state(args=["./crackme1",argv1])

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>官方脚本里直接懒得猜flag多少字节，直接构造了100个字节，然后以args=[file,argv]的方式送入entry_state就行了，其他的都一样，只是约束器结果要转化为byte类型的字节流还要用到一个eval函数，看以下代码：</font><br>

```python
#create a path group using the created initial state 
sm = project.factory.simulation_manager(initial_state)

#symbolically execute the program until we reach the wanted value of the instruction pointer
sm.explore(find=0x400602) #at this instruction the binary will print(the "correct" message)

found = sm.found[0]
#ask to the symbolic solver to get the value of argv1 in the reached state as a string
solution = found.solver.eval(argv1, cast_to=bytes)

print solution.strip('\x00')
# ais3{I_tak3_g00d_n0t3s}
```

