---
title: "CTF-Writeups"
summary: "writeups"
categories: ["Post","writeups","ctfs"]
tags: ["post","writeups"]
header_img: img/africa.PNG
#externalUrl: ""
#showSummary: true
date: 2023-06-26
draft: false
---


I Recently participated in the africa battle ctf 2023, In this blog I will cover some of the challenges I tackled. In all honesty, some challenges I tackled during the CTF and some after the CTF.

#### battleCTF Event Portal
![image](event.PNG)
This pwn Challenge was pretty easy, I wondered why it had less solves, but let's get into it.
We can see the challenge category is integer overflow. First I opened the c file given to see the flow of code.

![image](event2.PNG)

We see a call to puts which prints a statement then we see a printf followed by a scanf which prompts the user for a pass. It is then followed by an if function which we see calls bin/sh else it prints wrong password in the else function. So we need to get the pass so that we can execute the if function to get bin/sh. Looking at the category we see it is an integer overflow challenge. That right away gave me an idea of what I was going to do. 
When an arithmetic operation on two numbers results in a result that is larger than the largest value that the data type of the integers can represent, this phenomenon is known as integer overflow. This can result in unexpected and possibly inaccurate results since the operation's result will wrap around to the lowest number that the data type can support.

In C we know the max value is 0xffffffffffffffff . But we see to get the pass we need to do this function "pass * 0x726176656e70776eu == 0x407045989b3284aeu". 
[Theguyintuxedo](https://guyinatuxedo.github.io/35-integer_exploitation/puzzle/index.html) explains integer overflow better.

So to get the pass we can write a code to solve that.
```python
from z3 import *

get_pass = Solver()

x = BitVec("0", 64)

get_pass.add(((x * 0x726176656e70776eu) & 0xffffffffffffffff) == 0x407045989b3284aeu)

if get_pass.check() == sat:
    solution = get_pass.model()
    solution = hex(int(str(solution[x])))
    solution = solution[2:]

    # Reverse the value
    value = ""
    i = len(solution) / 2
    while i > 0:
        i -= 1
        y = solution[(i*2):(i*2) + 2]
        value += chr(int("0x" + y, 16))

    print("please give me the pass: " + value)
else:
    print ("Something must be wrong")
```
