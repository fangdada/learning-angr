# how2angr 

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>angr是一个强大平台无关的二进制分析框架，我个人学习angr的初心其实是为了对抗低强度的控制流平坦化混淆，后来学着学着发现符号执行非常值得深入研究一下，故有了这一系列文章。</font></br>

    <font size=2>这些文章中的例子都是angr-doc官方github仓库里的example，我主要是解析官方解题脚本并尽可能给出说明。除非例题特别简单，要懂这些脚本首先就要会用常规思路解出那些例题，所以比较难的题我也会放常规解，可能部分常规解我还没从我的GitHub搬运过来，所以链接可能是GitHub的。</font></br>

## 安装angr

`sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper`
`sudo pip install angr && sudo pip3 install angr`

## angr实例

- [helloworld](https://fanda.cloud/2019/03/13/angr%E5%AD%A6%E4%B9%A0-helloworld/)
> 最简单的入门例子
- [命令行输入](https://fanda.cloud/2019/03/13/angr%E5%AD%A6%E4%B9%A0-%E7%AC%AC%E4%BA%8C%E8%8A%82%E5%91%BD%E4%BB%A4%E8%A1%8C%E8%BE%93%E5%85%A5/)
> 当程序接受命令行参数输入时如何用angr求解
- [插入符号变量](https://fanda.cloud/2019/03/13/angr%E5%AD%A6%E4%B9%A0-%E7%AC%AC%E4%B8%89%E8%8A%82%E6%8F%92%E5%85%A5%E7%AC%A6%E5%8F%B7%E5%8F%98%E9%87%8F/)
> 当解题思路是求解某个变量的值时如何用angr完成
- [模拟执行MIPS](https://fanda.cloud/2019/03/13/angr%E5%AD%A6%E4%B9%A0-%E7%AC%AC%E5%9B%9B%E8%8A%82%E6%A8%A1%E6%8B%9F%E6%89%A7%E8%A1%8Cmips/)
> 题目是一个MIPS的debug trace日志，用angr的装载器的blob后端来模拟执行
- [爆破](https://fanda.cloud/2019/03/13/angr%E5%AD%A6%E4%B9%A0-%E7%AC%AC%E4%BA%94%E8%8A%82%E7%88%86%E7%A0%B4/)
> 用angr这种符号执行工具同样可以爆破
- [优化](https://github.com/fangdada/learning-angr/tree/master/ctf/%E4%BC%98%E5%8C%96)
> 当程序比较复杂或者angr执行异常慢怎么办
- [反Anti](https://github.com/fangdada/learning-angr/tree/master/ctf/%E5%8F%8Danti)
> 绕过程序中的anti-debug或者anti-run

- ...

