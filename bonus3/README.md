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
   0x080484fc <+8>:	sub    esp,0xa0                           <-- Space of 160 bytes for the stack frame
   0x08048502 <+14>:	mov    edx,0x80486f0                      <-- Load "r"
   0x08048507 <+19>:	mov    eax,0x80486f2                      <-- Load "/home/user/end/.pass"
   0x0804850c <+24>:	mov    DWORD PTR [esp+0x4],edx            <-- Set "r" as 2nd argument to fopen()
   0x08048510 <+28>:	mov    DWORD PTR [esp],eax                <-- Set "/home/user/end/.pass" as 1st argument to fopen()
   0x08048513 <+31>:	call   0x8048410 <fopen@plt>              <-- Call to fopen("/home/user/end/.pass", "r")
   0x08048518 <+36>:	mov    DWORD PTR [esp+0x9c],eax           <-- Store return value of fopen() to FILE *stream
   0x0804851f <+43>:	lea    ebx,[esp+0x18]                     <-- Load char buffer[132]
   0x08048523 <+47>:	mov    eax,0x0                            <-- Set '\0' as the overwrite byte and 2nd argument to memset()
   0x08048528 <+52>:	mov    edx,0x21                           <-- Set 33 * 4 = 132 the counter
   0x0804852d <+57>:	mov    edi,ebx                            <-- Set char *buffer as 1st argument to memset()
   0x0804852f <+59>:	mov    ecx,edx                            <-- Set 132 as the 3rd argument to memset()
   0x08048531 <+61>:	rep stos DWORD PTR es:[edi],eax           <-- Call to memset(buffer, '\0', 132)
   0x08048533 <+63>:	cmp    DWORD PTR [esp+0x9c],0x0           <-- Compare if FILE *stream is NULL
   0x0804853b <+71>:	je     0x8048543 <main+79>                <-- If it is, jump to main+79
   0x0804853d <+73>:	cmp    DWORD PTR [ebp+0x8],0x2            <-- Compare int argc and 2
   0x08048541 <+77>:	je     0x804854d <main+89>                <-- If it is, jump to main+89
   0x08048543 <+79>:	mov    eax,0xffffffff                     <-- Else, put -1 in eax
   0x08048548 <+84>:	jmp    0x8048615 <main+289>               <-- Go to +289 (return(-1))
   0x0804854d <+89>:	lea    eax,[esp+0x18]                     <-- Load char buffer[132]
   0x08048551 <+93>:	mov    edx,DWORD PTR [esp+0x9c]           <-- Load FILE *stream
   0x08048558 <+100>:	mov    DWORD PTR [esp+0xc],edx         <-- Set FILE *stream as 4th argument to fread()
   0x0804855c <+104>:	mov    DWORD PTR [esp+0x8],0x42        <-- Set 66 as the 3rd argument to fread()
   0x08048564 <+112>:	mov    DWORD PTR [esp+0x4],0x1         <-- Set 1 as the 2nd argument to fread()
   0x0804856c <+120>:	mov    DWORD PTR [esp],eax             <-- Set char buffer[132] as 1st argument to fread()
   0x0804856f <+123>:	call   0x80483d0 <fread@plt>           <-- Call to fread(buffer, 1, 66, stream)
   0x08048574 <+128>:	mov    BYTE PTR [esp+0x59],0x0         <-- Set 0 int index
   0x08048579 <+133>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[]
   0x0804857c <+136>:	add    eax,0x4                         <-- Add 4 to char *argv[]
   0x0804857f <+139>:	mov    eax,DWORD PTR [eax]             <-- Load char *argv[1]
   0x08048581 <+141>:	mov    DWORD PTR [esp],eax             <-- Set char *argv[1] as 1st argument to atoi()
   0x08048584 <+144>:	call   0x8048430 <atoi@plt>            <-- Call to atoi(argv[1])
   0x08048589 <+149>:	mov    BYTE PTR [esp+eax*1+0x18],0x0   <-- Set buffer[index] to '\0'
   0x0804858e <+154>:	lea    eax,[esp+0x18]                  <-- Load char buffer[132]
   0x08048592 <+158>:	lea    edx,[eax+0x42]                  <-- Load address &buffer[66]
   0x08048595 <+161>:	mov    eax,DWORD PTR [esp+0x9c]        <-- Load FILE *stream
   0x0804859c <+168>:	mov    DWORD PTR [esp+0xc],eax         <-- Set FILE *stream as 4th argument to fread()
   0x080485a0 <+172>:	mov    DWORD PTR [esp+0x8],0x41        <-- Set 65 as the 3rd argument to fread()
   0x080485a8 <+180>:	mov    DWORD PTR [esp+0x4],0x1         <-- Set 1 as the 2nd argument to fread()
   0x080485b0 <+188>:	mov    DWORD PTR [esp],edx             <-- Set &buffer[66] as 1st argument to fread()
   0x080485b3 <+191>:	call   0x80483d0 <fread@plt>           <-- Call to fread(&buffer[66], 1, 65, stream)
   0x080485b8 <+196>:	mov    eax,DWORD PTR [esp+0x9c]        <-- Load FILE *stream
   0x080485bf <+203>:	mov    DWORD PTR [esp],eax             <-- Set FILE *stream as 1st argument to fclose()
   0x080485c2 <+206>:	call   0x80483c0 <fclose@plt>          <-- Call to fclose(stream)
   0x080485c7 <+211>:	mov    eax,DWORD PTR [ebp+0xc]         <-- Load char *argv[]
   0x080485ca <+214>:	add    eax,0x4                         <-- Add 4 to char *argv[]
   0x080485cd <+217>:	mov    eax,DWORD PTR [eax]             <-- Load char *argv[1]
   0x080485cf <+219>:	mov    DWORD PTR [esp+0x4],eax         <-- Set char *argv[1] as 2nd argument to strcmp()
   0x080485d3 <+223>:	lea    eax,[esp+0x18]                  <-- Load char buffer[132]
   0x080485d7 <+227>:	mov    DWORD PTR [esp],eax             <-- Set char buffer[132] as 1st argument to strcmp()
   0x080485da <+230>:	call   0x80483b0 <strcmp@plt>          <-- Call to strcmp(buffer, argv[1])
   0x080485df <+235>:	test   eax,eax                         <-- Test if strcmp() returned 0
   0x080485e1 <+237>:	jne    0x8048601 <main+269>            <-- If it is not, jump to main+269
   0x080485e3 <+239>:	mov    DWORD PTR [esp+0x8],0x0         <-- Set 0 as the 3rd argument to execl()
   0x080485eb <+247>:	mov    DWORD PTR [esp+0x4],0x8048707   <-- Set "sh" as the 2nd argument to execl()
   0x080485f3 <+255>:	mov    DWORD PTR [esp],0x804870a       <-- Set "/bin/sh" as the 1st argument to execl()
   0x080485fa <+262>:	call   0x8048420 <execl@plt>           <-- Call to execl("/bin/sh", "sh", 0)
   0x080485ff <+267>:	jmp    0x8048610 <main+284>            <-- go to +284 (return(0))
   0x08048601 <+269>:	lea    eax,[esp+0x18]                  <-- Load char buffer[132]
   0x08048605 <+273>:	add    eax,0x42                        <-- Add 66 to char buffer[132]
   0x08048608 <+276>:	mov    DWORD PTR [esp],eax             <-- Set &buffer[66] as 1st argument to puts()
   0x0804860b <+279>:	call   0x80483e0 <puts@plt>            <-- Call to puts(&buffer[66])
   0x08048610 <+284>:	mov    eax,0x0                         <-- Set 0 as the return value
   0x08048615 <+289>:	lea    esp,[ebp-0x8]                   <-- Restore esp to original value
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
