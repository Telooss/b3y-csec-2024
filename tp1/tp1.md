# Part I : Filtrey des paqueys

🌞 Proposer une configuration restrictive de firewalld

```
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 10.1.1.0/24
  services:
  ports: 22/tcp
  protocols:
  forward: yes
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
```

# Part II : PAM

🌞 Proposer une configuration de politique de mot de passe

```
[telos@vbox ~]$ cat /etc/security/pwquality.conf | grep -E "^#" -v
minlen = 14       # length minimum
dcredit = -1      # chiffre
ucredit = -1      # majuscule
lcredit = -1      # minuscule
ocredit = -1      # special char
enforce_for_root  # règle strict pour ne pas avoir seulement une alerte
```

# Part III : OpenSSH

Mot de passe : T4sT3stD0fus3?  (tu t'es co donc pas besoin de tout mettre si ?)

# Part IV : Gestion d'utilisateurs# PAM 
# Utilisateurs Groups
Utilisaton du script suivant : [users_group.sh](./users_groups.sh) (PS : j'ai rajouter logs pour voir ce que je fais)

```
[telos@vbox ~]$ sudo ./users_groups.sh
[sudo] password for telos:
2025-02-24 15:01:54 - Début de la gestion des utilisateurs.
2025-02-24 15:01:55 - Création de l'utilisateur : suha
2025-02-24 15:01:55 - Groupe principal créé : suha
2025-02-24 15:01:55 - Utilisateur suha créé avec le groupe principal suha
2025-02-24 15:01:55 - Groupe secondaire créé : managers
2025-02-24 15:01:55 - Groupe secondaire créé : admins
usermod: group '' does not exist
2025-02-24 15:01:55 - Ajout de suha aux groupes secondaires : managers  admins
2025-02-24 15:01:55 - Création de l'utilisateur : daniel
2025-02-24 15:01:55 - Groupe principal créé : daniel
2025-02-24 15:01:56 - Utilisateur daniel créé avec le groupe principal daniel
2025-02-24 15:01:56 - Groupe secondaire créé : sysadmins
usermod: group '' does not exist
2025-02-24 15:01:56 - Ajout de daniel aux groupes secondaires : admins  sysadmins
2025-02-24 15:01:56 - Création de l'utilisateur : liam
2025-02-24 15:01:56 - Groupe principal créé : liam
2025-02-24 15:01:56 - Utilisateur liam créé avec le groupe principal liam
2025-02-24 15:01:56 - Ajout de liam aux groupes secondaires : admins
2025-02-24 15:01:56 - Création de l'utilisateur : noah
2025-02-24 15:01:56 - Groupe principal créé : noah
2025-02-24 15:01:57 - Utilisateur noah créé avec le groupe principal noah
2025-02-24 15:01:57 - Groupe secondaire créé : artists
usermod: group '' does not exist
2025-02-24 15:01:57 - Ajout de noah aux groupes secondaires : managers  artists
2025-02-24 15:01:57 - Création de l'utilisateur : alysha
2025-02-24 15:01:57 - Groupe principal créé : alysha
2025-02-24 15:01:57 - Utilisateur alysha créé avec le groupe principal alysha
2025-02-24 15:01:57 - Ajout de alysha aux groupes secondaires : artists
2025-02-24 15:01:57 - Création de l'utilisateur : rose
2025-02-24 15:01:57 - Groupe principal créé : rose
2025-02-24 15:01:58 - Utilisateur rose créé avec le groupe principal rose
2025-02-24 15:01:58 - Groupe secondaire créé : devs
usermod: group '' does not exist
2025-02-24 15:01:58 - Ajout de rose aux groupes secondaires : artists  devs
2025-02-24 15:01:58 - Création de l'utilisateur : sadia
2025-02-24 15:01:58 - Groupe principal créé : sadia
2025-02-24 15:01:58 - Utilisateur sadia créé avec le groupe principal sadia
2025-02-24 15:01:58 - Ajout de sadia aux groupes secondaires : devs
2025-02-24 15:01:58 - Création de l'utilisateur : jakub
2025-02-24 15:01:58 - Groupe principal créé : jakub
2025-02-24 15:01:59 - Utilisateur jakub créé avec le groupe principal jakub
2025-02-24 15:01:59 - Ajout de jakub aux groupes secondaires : devs
2025-02-24 15:01:59 - Création de l'utilisateur : lev
2025-02-24 15:01:59 - Groupe principal créé : lev
2025-02-24 15:01:59 - Utilisateur lev créé avec le groupe principal lev
2025-02-24 15:01:59 - Ajout de lev aux groupes secondaires : devs
2025-02-24 15:01:59 - Création de l'utilisateur : grace
2025-02-24 15:01:59 - Groupe principal créé : grace
2025-02-24 15:02:00 - Utilisateur grace créé avec le groupe principal grace
2025-02-24 15:02:00 - Groupe secondaire créé : rh
2025-02-24 15:02:00 - Ajout de grace aux groupes secondaires : rh
2025-02-24 15:02:00 - Création de l'utilisateur : lucia
2025-02-24 15:02:00 - Groupe principal créé : lucia
2025-02-24 15:02:00 - Utilisateur lucia créé avec le groupe principal lucia
2025-02-24 15:02:00 - Ajout de lucia aux groupes secondaires : rh
2025-02-24 15:02:00 - Création de l'utilisateur : oliver
2025-02-24 15:02:00 - Groupe principal créé : oliver
2025-02-24 15:02:01 - Utilisateur oliver créé avec le groupe principal oliver
2025-02-24 15:02:01 - Ajout de oliver aux groupes secondaires : rh
2025-02-24 15:02:01 - Création de l'utilisateur : nginx
2025-02-24 15:02:01 - Groupe principal créé : nginx
2025-02-24 15:02:01 - Utilisateur nginx créé avec le groupe principal nginx
2025-02-24 15:02:01 - Pas de groupes secondaires pour nginx.
2025-02-24 15:02:01 - Gestion des utilisateurs terminée.



# petit check pour vérifier que tout est bon
[telos@vbox ~]$ getent passwd | grep suha
suha:x:1002:1002::/home/suha:/bin/bash
[telos@vbox ~]$ getent group | grep rh
rh:x:1017:grace,lucia,oliver
[telos@vbox ~]$ cd ..
[telos@vbox home]$ ls
alysha  daniel  grace  it4  jakub  lev  liam  lucia  nginx  noah  oliver  rose  sadia  suha  telos
```
# Permissions

Création de tout les dossiers/fichiers : 

```bash
[telos@vbox ~]$
sudo mkdir -p /data/projects/the_zoo
sudo mkdir -p /data/projects/website
sudo mkdir -p /data/projects/client_data/client1
sudo mkdir -p /data/projects/client_data/client2
sudo mkdir -p /data/projects/zoo_app
sudo mkdir -p /data/conf
sudo touch /data/projects/README.docx
sudo touch /data/projects/the_zoo/ideas.docx
sudo touch /data/projects/website/index.html
sudo touch /data/projects/client_data/client1/data.docx
sudo touch /data/projects/client_data/client2/data.docx
sudo touch /data/projects/zoo_app/zoo_app
sudo touch /data/conf/test.conf
[sudo] password for telos:
[telos@vbox ~]$
```

Droits Posix : 

```bash
[telos@vbox ~]$ sudo chmod 750 /data/
sudo chown root:managers /data/projects/
sudo chmod 444 /data/projects/README.docx
[telos@vbox ~]$
```

Droits ACL : 

```
[telos@vbox ~]$ sudo ls -alR /data
/data:
total 0
drwxr-x---.  4 root root      34 Mar  2 22:06 .
dr-xr-xr-x. 19 root root     247 Mar  2 22:06 ..
drwxr-xr-x+  2 root root      23 Mar  2 22:06 conf
drwxr-xr-x.  6 root managers  89 Mar  2 22:06 projects

/data/conf:
total 0
drwxr-xr-x+ 2 root root 23 Mar  2 22:06 .
drwxr-x---. 4 root root 34 Mar  2 22:06 ..
-rw-r--r--+ 1 root root  0 Mar  2 22:06 test.conf

/data/projects:
total 4
drwxr-xr-x. 6 root managers 89 Mar  2 22:06 .
drwxr-x---. 4 root root     34 Mar  2 22:06 ..
drwxr-xr-x. 4 root root     36 Mar  2 22:06 client_data
-r--r--r--. 1 root root      0 Mar  2 22:06 README.docx
drwxrwxr-x+ 2 root root     24 Mar  2 22:06 the_zoo
drwxrwxr-x+ 2 root root     24 Mar  2 22:06 website
drwxr-xr-x+ 2 root root     21 Mar  2 22:06 zoo_app

/data/projects/client_data:
total 0
drwxr-xr-x. 4 root root     36 Mar  2 22:06 .
drwxr-xr-x. 6 root managers 89 Mar  2 22:06 ..
drwxrwxr-x+ 2 root root     23 Mar  2 22:06 client1
drwxrwxr-x+ 2 root root     23 Mar  2 22:06 client2

/data/projects/client_data/client1:
total 0
drwxrwxr-x+ 2 root root 23 Mar  2 22:06 .
drwxr-xr-x. 4 root root 36 Mar  2 22:06 ..
-rw-rw-r--+ 1 root root  0 Mar  2 22:06 data.docx

/data/projects/client_data/client2:
total 0
drwxrwxr-x+ 2 root root 23 Mar  2 22:06 .
drwxr-xr-x. 4 root root 36 Mar  2 22:06 ..
-rw-rw-r--+ 1 root root  0 Mar  2 22:06 data.docx

/data/projects/the_zoo:
total 4
drwxrwxr-x+ 2 root root     24 Mar  2 22:06 .
drwxr-xr-x. 6 root managers 89 Mar  2 22:06 ..
-rw-rw-r--+ 1 root root      0 Mar  2 22:06 ideas.docx

/data/projects/website:
total 0
drwxrwxr-x+ 2 root root     24 Mar  2 22:06 .
drwxr-xr-x. 6 root managers 89 Mar  2 22:06 ..
-rw-rw-r--+ 1 root root      0 Mar  2 22:06 index.html

/data/projects/zoo_app:
total 0
drwxr-xr-x+ 2 root root     21 Mar  2 22:06 .
drwxr-xr-x. 6 root managers 89 Mar  2 22:06 ..
-rwsrwxr-x+ 1 root sadia     0 Mar  2 22:06 zoo_app
[telos@vbox ~]$ sudo getfacl -R /data
getfacl: Removing leading '/' from absolute path names
# file: data
# owner: root
# group: root
user::rwx
group::r-x
other::---

# file: data/projects
# owner: root
# group: managers
user::rwx
group::r-x
other::r-x

# file: data/projects/the_zoo
# owner: root
# group: root
user::rwx
user:suha:rwx
group::r-x
group:managers:r-x
group:artists:rwx
group:devs:rwx
mask::rwx
other::r-x
default:user::rwx
default:user:suha:rwx
default:group::r-x
default:group:managers:r-x
default:group:artists:rwx
default:group:devs:rwx
default:mask::rwx
default:other::r-x

# file: data/projects/the_zoo/ideas.docx
# owner: root
# group: root
user::rw-
user:suha:rw-
group::r--
group:managers:r--
group:artists:rw-
group:devs:r--
mask::rw-
other::r--

# file: data/projects/website
# owner: root
# group: root
user::rwx
user:daniel:rwx
user:alysha:rwx
user:rose:rwx
user:nginx:r-x
group::r-x
group:managers:r-x
group:artists:r-x
group:devs:rwx
mask::rwx
other::r-x

# file: data/projects/website/index.html
# owner: root
# group: root
user::rw-
user:daniel:rw-
user:alysha:rw-
user:nginx:r--
group::r--
group:managers:r--
group:artists:r--
group:devs:rw-
mask::rw-
other::r--

# file: data/projects/client_data
# owner: root
# group: root
user::rwx
group::r-x
other::r-x

# file: data/projects/client_data/client1
# owner: root
# group: root
user::rwx
user:grace:rwx
user:oliver:rwx
group::r-x
group:managers:r-x
group:rh:r-x
mask::rwx
other::r-x

# file: data/projects/client_data/client1/data.docx
# owner: root
# group: root
user::rw-
user:grace:rw-
user:oliver:rw-
group::r--
mask::rw-
other::r--

# file: data/projects/client_data/client2
# owner: root
# group: root
user::rwx
user:noah:rwx
user:grace:rwx
user:lucia:rwx
group::r-x
group:managers:r-x
group:rh:r-x
mask::rwx
other::r-x

# file: data/projects/client_data/client2/data.docx
# owner: root
# group: root
user::rw-
user:grace:rw-
user:lucia:rw-
group::r--
mask::rw-
other::r--

# file: data/projects/zoo_app
# owner: root
# group: root
user::rwx
user:suha:r-x
user:sadia:r-x
user:jakub:r-x
group::r-x
mask::r-x
other::r-x

# file: data/projects/zoo_app/zoo_app
# owner: root
# group: sadia
# flags: s--
user::rwx
user:suha:rw-
user:sadia:rw-
user:jakub:r--
group::r--
mask::rwx
other::r-x

# file: data/projects/README.docx
# owner: root
# group: root
user::r--
group::r--
other::r--

# file: data/conf
# owner: root
# group: root
user::rwx
user:daniel:r-x
user:rose:r-x
group::r-x
group:admins:r-x
group:sysadmins:r-x
mask::r-x
other::r-x

# file: data/conf/test.conf
# owner: root
# group: root
user::rw-
user:daniel:r--
user:rose:r--
group::r--
group:admins:r--
group:sysadmins:r--
mask::r--
other::r--

[telos@vbox ~]$ sudo lsattr -R /data
---------------------- /data/projects

/data/projects:
---------------------- /data/projects/the_zoo

/data/projects/the_zoo:
---------------------- /data/projects/the_zoo/ideas.docx

---------------------- /data/projects/website

/data/projects/website:
---------------------- /data/projects/website/index.html

---------------------- /data/projects/client_data

/data/projects/client_data:
---------------------- /data/projects/client_data/client1

/data/projects/client_data/client1:
---------------------- /data/projects/client_data/client1/data.docx

---------------------- /data/projects/client_data/client2

/data/projects/client_data/client2:
---------------------- /data/projects/client_data/client2/data.docx


---------------------- /data/projects/zoo_app

/data/projects/zoo_app:
---------------------- /data/projects/zoo_app/zoo_app

----i----------------- /data/projects/README.docx

---------------------- /data/conf

/data/conf:
---------------------- /data/conf/test.conf

[telos@vbox ~]$

```
# Sudo 

```
Defaults !authenticate

%sysadmins ALL=(root) NOPASSWD: ALL

%artists ALL=(sadia) NOPASSWD: /bin/ls /bin/cat /usr/bin/vi /usr/bin/file /data/*

alysha ALL=(suha) NOPASSWD: /bin/cat /data/projects/the_zoo/ideas.docx

%devs ALL=(root) NOPASSWD: /usr/bin/dnf install *

jakub ALL=(liam) NOPASSWD: /usr/bin/python

%admins ALL=(daniel) NOPASSWD: /usr/bin/free, /usr/bin/top, /bin/df, /usr/bin/du, /bin/ps, /sbin/ip

lev ALL=(daniel) NOPASSWD: /usr/bin/openssl, /usr/bin/dig, /bin/ping, /usr/bin/curl


```
Voici une meilleure conf quand même 
```

Defaults        !authenticate

Defaults        !noexec

%sysadmins ALL=(root) NOPASSWD: ALL

Defaults:%artists noexec
%artists ALL=(sadia) NOPASSWD: /bin/ls, /bin/cat, /usr/bin/vi, /usr/bin/file, /data/*

Defaults:alysha noexec
alysha ALL=(suha) NOPASSWD: /bin/cat /data/projects/the_zoo/ideas.docx


%devs ALL=(root) NOPASSWD: /usr/bin/dnf install *

Defaults:jakub noexec
jakub ALL=(liam) NOPASSWD: /usr/bin/python -c "print('Test')"

Defaults:%admins noexec
%admins ALL=(daniel) NOPASSWD: /usr/bin/free, /usr/bin/top, /bin/df, /usr/bin/du, /bin/ps, /sbin/ip

lev ALL=(daniel) NOPASSWD: /usr/bin/openssl, /usr/bin/dig, /bin/ping, /usr/bin/curl

```

# V. KTP (Kill the patrick)       [Je sé c'est FTP c'est ue vanne enfaite]

FTP est juste un prétexte ici, et c'est pas rare de le croiser encore ; étant un simple protocole de partage de fichiers, ça nous fournit un cas d'utilisation idéal pour jouer avec des utilisateurs, et rendre (un peu) utile la partie précédente.

Ce qu'on trouve le plus maintenant, c'est pas juste du FTP en clair mais plutôt du SFTP (à travers SSH) ou FTP avec TLS (parfois appelé FTPS).

![tls or ssl](./img/tls.jpg)

🌞 **Mettre en place un serveur FTP + TLS**



```
[root@vbox telos]# ls -ld /etc/ftp/private /etc/ftp/certs
drwxr-xr-x. 2 root root 24 Mar  2 22:49 /etc/ftp/certs
drwxr-xr-x. 2 root root 24 Mar  2 22:48 /etc/ftp/private
[root@vbox telos]# ls -l /etc/ftp/private/vsftpd.key
ls -l /etc/ftp/certs/vsftpd.pem
-rw-------. 1 root root 1704 Mar  2 22:48 /etc/ftp/private/vsftpd.key
-rw-------. 1 root root 1399 Mar  2 22:49 /etc/ftp/certs/vsftpd.pem
[root@vbox telos]# grep -E "^(anonymous_enable|local_enable|write_enable|chroot_local_user|ssl_enable|rsa_cert_file|rsa_private_key_file|force_local_data_ssl|force_local_logins_ssl|ssl_tlsv1|ssl_tlsv1_1|ssl_tlsv1_2|ssl_sslv2|ssl_sslv3|ssl_ciphers|require_ssl_reuse|pasv_enable|pasv_min_port|pasv_max_port|local_root|xferlog_enable|xferlog_file)=" /etc/vsftpd/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
ssl_enable=YES
rsa_cert_file=/etc/ftp/certs/vsftpd.pem
rsa_private_key_file=/etc/ftp/private/vsftpd.key
ssl_tlsv1_1=YES
ssl_tlsv1_2=YES
ssl_sslv2=NO
ssl_sslv3=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_ciphers=HIGH
require_ssl_reuse=NO
pasv_enable=YES
pasv_min_port=30000
pasv_max_port=30100
local_root=/var/ftp
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
[root@vbox telos]# sudo systemctl status vsftpd
● vsftpd.service - Vsftpd ftp daemon
     Loaded: loaded (/usr/lib/systemd/system/vsftpd.service; enabled; preset: disabled)
     Active: active (running) since Sun 2025-03-02 22:55:12 CET; 1min 45s ago
    Process: 1382 ExecStart=/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf (code=exited, status=0/SUCCESS)
   Main PID: 1383 (vsftpd)
      Tasks: 1 (limit: 23155)
     Memory: 1.1M
        CPU: 13ms
     CGroup: /system.slice/vsftpd.service
             └─1383 /usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf

Mar 02 22:55:12 vbox systemd[1]: Starting Vsftpd ftp daemon...
Mar 02 22:55:12 vbox systemd[1]: Started Vsftpd ftp daemon.
[root@vbox telos]# sudo firewall-cmd --list-all | grep services
sudo firewall-cmd --list-ports
  services: ftp
3845/tcp 30000-30100/tcp
[root@vbox telos]# sudo ss -tulpn | grep :21
tcp   LISTEN 0      32           0.0.0.0:21        0.0.0.0:*    users:(("vsftpd",pid=1383,fd=3))
```

> Vous pouvez tester que vos utilisateurs de la partie précédente ont bien accès à leurs fichiers/dossiers *via* FTP maintenant :)


