# sym-write

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>这题就让我们学习一下angr如何利用约束器计算全局变量吧，假设有这样一道题目（官方源码）：</font></br>

```C
#include <stdio.h>

char u=0;
int main(void)
{
	int i, bits[2]={0,0};
	for (i=0; i<8; i++) {
		bits[(u&(1<<i))!=0]++;
	}
	if (bits[0]==bits[1]) {
		printf("you win!");
	}
	else {
		printf("you lose!");
	}
	return 0;
}

```

&nbsp;&nbsp;&nbsp;&nbsp;<font size=2>那么题目很简单，需要得到一个特殊的u值使得条件成立输出you win就行了，利用angr state的memory方法的store函数就可以把符号变量插入到全局变量中然后老样子利用explore约束求到最终解，这题就这样没其他知识点了，所以直接放脚本：</font></br>

```python
import angr
import claripy

def main():
	p = angr.Project('./issue', load_options={"auto_load_libs": False})

	# By default, all symbolic write indices are concretized.
	state = p.factory.entry_state(add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES})

	u = claripy.BVS("u", 8)
	state.memory.store(0x804a021, u)

	sm = p.factory.simulation_manager(state)

	def correct(state):
		try:
			return b'win' in state.posix.dumps(1)
		except:
			return False
	def wrong(state):
		try:
			return b'lose' in state.posix.dumps(1)
		except:
			return False

	sm.explore(find=correct, avoid=wrong)

	# Alternatively, you can hardcode the addresses.
	# sm.explore(find=0x80484e3, avoid=0x80484f5)

	return sm.found[0].solver.eval(u)


def test():
	assert '240' in str(main())


if __name__ == '__main__':
	print(repr(main()))
```

