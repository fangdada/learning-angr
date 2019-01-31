# DEFCAMP r100

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>作为学习angr框架的第一个demo自然是要越简单越好，就从defcamp_r100这道逆向入门题入手了，在这里就解析官方提供的解题脚本了，先来看看IDA伪代码：</font></br>

```C
signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  signed __int64 result; // rax
  char s; // [rsp+0h] [rbp-110h]
  unsigned __int64 v5; // [rsp+108h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the password: ", a2, a3);
  if ( !fgets(&s, 255, stdin) )
    return 0LL;
  if ( (unsigned int)sub_4006FD((__int64)&s) )
  {
    puts("Incorrect password!");
    result = 1LL;
  }
  else
  {
    puts("Nice!");
    result = 0LL;
  }
  return result;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>主函数非常简单，可以看到只要过了sub_4006FD这个判断函数就能成功完成这一题了，sub_4006FD：</font></br>

```C
signed __int64 __fastcall sub_4006FD(__int64 strings)
{
  signed int i; // [rsp+14h] [rbp-24h]
  const char *v3; // [rsp+18h] [rbp-20h]
  const char *v4; // [rsp+20h] [rbp-18h]
  const char *v5; // [rsp+28h] [rbp-10h]

  v3 = "Dufhbmf";
  v4 = "pG`imos";
  v5 = "ewUglpt";
  for ( i = 0; i <= 11; ++i )
  {
    if ( (&v3)[i % 3][2 * (i / 3)] - *(char *)(i + strings) != 1 )
      return 1LL;
  }
  return 0LL;
}
```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>思路就不说了太简单，如果是用常规的逆向方法来做的话就是写出加密逆运算，然后对v3这个地址开始的二维数组密文求逆就可以得到结果了，或者利用z3-solver也可以。但是我们既然是来学习angr框架的，所以我们就要用angr这个强大的工具来解出这一题：</font></br>

```python
import angr
p=angr.Project('./r100')
simgr = p.factory.simulation_manager(p.factory.full_init_state())
```



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>首先使用angr的Project方法加载二进制文件，这就跟pwntools里的process类似，这里很简单。然后用到了factory方法，顾名思义，factory提供了一系列的方法，simulation_manager是angr里的一个非常重要的模拟器，参数里的full_init_state()的意思就是加载二进制文件后初始化好除了从入口点开始执行的一系列环境，作用非常相似entry_state()，类似的还有一个方法blank_state()就是加载文件后什么初始化工作都不做。加载完毕后我们就可以使用例如run，step等函数进行模拟执行了，看我们接下来的代码：</font></br>

```python
simgr.explore(find=0x400844, avoid=0x400855)

return simgr.found[0].posix.dumps(0).strip(b'\0\n')
```



&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>explore函数也是属于angr的simulation manager的，利用这个函数可以探索出我们想要的state和要达到这个state所需的约束条件。参数find的意思就是要到达的地址，在这里就是题目中的puts("Nice!");的地址，avoid同样顾名思义就是要避免的错误条件，也就是puts("Incorrect password!");</font></br>

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>随后就可以根据simulation explore返回的正确结果解析出来就是我们最终的求解了，是不是很简单？连求逆算法都不用写了，造福懒人的福音哈哈哈。不过explore的原理是非常值得去学习一番的。接下来放一下最终结果：</font></br>

```bash
➜  defcamp_r100 git:(master) python solve.py
Code_Talkers�������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������
➜  defcamp_r100 git:(master) ./r100
Enter the password: Code_Talkers
Nice!
➜  defcamp_r100 git:(master) 
```



