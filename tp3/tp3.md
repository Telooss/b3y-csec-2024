# Rapport de TP – Hardening des systèmes avec SELinux  
**Durée :** 3h  
**Nom :** BOURDONCLE Alan  
**Date :** 08/04/2025

**Machine utilisée :** Rocky Linux 9 (sans interface graphique)

---

# 1. Aperçu du lab

Le TP vise à sécuriser un serveur web Rocky Linux en appliquant le principe de défense en profondeur.
Nous devons configurer une maquette fidèle du serveur final, tester les mesures de sécurité, et documenter toutes les actions en autonomie.

# 2. Objectifs du lab

Les objectifs de ce lab sont multiples :

- Découverte et prise en main de SELinux
- Durcissement partiel du système

# 3.0 Les consignes
# 3.1 Installation du système d’exploitation

### Objectifs :
- Installer Rocky Linux 9 minimal
- Appliquer les dernières mises à jour de sécurité

### Commandes utilisées :

```
sudo dnf update -y
```

# 3.2. Sécurisation de l’administration du serveur

## Renforcement de la configuration SSH

Fichier modifié :
``/etc/ssh/sshd_config``

Paramètres ajoutés/modifiés :
```
PermitRootLogin no
PasswordAuthentication no
AllowUsers telos
```
## Clé SSH

- Génération de la clé : ``ssh-keygen -t ed25519 -C "telos@selinux"``
- Copie sur le serveur : ``ssh-copy-id telos@192.168.170.10``

## Redémarrage SSH

```
sudo systemctl restart sshd
```

## Configuration du pare-feu (firewalld)

```
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

# 3.3 Installation d'un serveur Web

## Installation Apache

```
sudo dnf install httpd -y
sudo systemctl enable --now httpd
```

## Vérification du service

```
[telos@selinux ~]$ sudo systemctl status httpd
[sudo] password for telos:
● httpd.service - The Apache HTTP Server
     Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled; preset: disabled)
     Active: active (running) since Thu 2025-04-03 11:48:48 CEST; 43min ago
       Docs: man:httpd.service(8)
   Main PID: 36177 (httpd)
     Status: "Total requests: 3; Idle/Busy workers 100/0;Requests/sec: 0.00115; Bytes served/sec:   9>
      Tasks: 177 (limit: 23141)
     Memory: 25.9M
        CPU: 5.071s
     CGroup: /system.slice/httpd.service
             ├─36177 /usr/sbin/httpd -DFOREGROUND
             ├─36178 /usr/sbin/httpd -DFOREGROUND
             ├─36179 /usr/sbin/httpd -DFOREGROUND
             ├─36180 /usr/sbin/httpd -DFOREGROUND
             └─36181 /usr/sbin/httpd -DFOREGROUND

Apr 03 11:48:48 selinux systemd[1]: Starting The Apache HTTP Server...
Apr 03 11:48:48 selinux httpd[36177]: AH00558: httpd: Could not reliably determine the server's fully>
Apr 03 11:48:48 selinux httpd[36177]: Server configured, listening on: port 80
Apr 03 11:48:48 selinux systemd[1]: Started The Apache HTTP Server.
```

## Accès via curl

```
[telos@selinux ~]$ curl localhost | head -n 20
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  7620  100  7620    <!doctype html>     0 --:--:-- --:--:-- --:--:--     0
<html>
  <head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
0     0   744k      0 --:--:-- --:--:-- --:--:--  744k
    <title>HTTP Server Test Page powered by: Rocky Linux</title>
    <style type="text/css">
      /*<![CDATA[*/

      html {
        height: 100%;
        width: 100%;
      }
        body {
  background: rgb(20,72,50);
  background: -moz-linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%)  ;
  background: -webkit-linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%) ;
  background: linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%);
  background-repeat: no-repeat;
  background-attachment: fixed;
```

## Vérification SELinux

```
[telos@selinux ~]$ sestatus
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33
```

## Modes de SELinux

| Mode | Description |
|------|-------------|
| Enforcing | Applique strictement les politiques de sécurité |
| Permissive | N’applique pas, mais journalise ce qu’il bloquerait (pratique lors de phase de test)|
| Disabled | Complètement désactivé |

## Profil SELinux en « enforce » mais mal adapté

SELinux **bloque les actions non autorisées**, ce qui peut empêcher un service de fonctionner.

**Exemple :**
Si Apache lit un fichier dans /srv/monsite/ sans le bon contexte (httpd_sys_content_t), alors en mode enforce, l'accès est refusé → le site affiche une erreur 403 ou ne prend pas en compte le fichier et affiche la page par défaut.

# 3.4 Modification d’un profil SELinux

### Contexte des fichiers Apache :

```
[telos@selinux html]$ ls -Z /var/www/html/
unconfined_u:object_r:httpd_sys_content_t:s0 index.html
```

### Contexte du processus :

```
[telos@selinux ~]$ ps -eZ | grep httpd
system_u:system_r:httpd_t:s0      36177 ?        00:00:00 httpd
system_u:system_r:httpd_t:s0      36178 ?        00:00:00 httpd
system_u:system_r:httpd_t:s0      36179 ?        00:00:04 httpd
system_u:system_r:httpd_t:s0      36180 ?        00:00:04 httpd
system_u:system_r:httpd_t:s0      36181 ?        00:00:04 httpd
```

### Mode "enforce" sur le profil apache

```
[telos@selinux html]$ sudo setenforce 1
```

```
[telos@selinux html]$ curl http://localhost
"Test Apache"
```

Le site fonctionne car les fichiers ont le bon contexte httpd_sys_content_t.

### Changement de DocumentRoot

```
[telos@selinux html]$ sudo setenforce 0
[telos@selinux html]$ sudo mkdir -p /srv/srv/srv_1
[telos@selinux html]$ echo "Test Apache SELinux" | sudo tee /srv/srv/srv_1/index.html
Test Apache SELinux
[telos@selinux html]$ cat /srv/srv/srv_1/index.html
Test Apache SELinux
```

Modification ``/etc/httpd/conf/httpd.conf`` :

```
DocumentRoot "/srv/srv/srv_1"
<Directory "/srv/srv/srv_1">
    Require all granted
</Directory>
```

Restart du service Apache :

```
[telos@selinux html]$ sudo systemctl restart httpd
```

Apache fonctionne en mode permissif, même si les contextes SELinux ne sont pas corrects.

Activation du mode "enforce" puis test du service :

```
[telos@selinux html]$ sudo setenforce 1
```

```
[telos@selinux html]$ curl http://localhost
<!doctype html>
<html>
  <head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>HTTP Server Test Page powered by: Rocky Linux</title>
    <style type="text/css">
      /*<![CDATA[*/

      html {
        height: 100%;
        width: 100%;
      }
        body {
  background: rgb(20,72,50);
  background: -moz-linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%)  ;
  background: -webkit-linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%) ;
  background: linear-gradient(180deg, rgba(23,43,70,1) 30%, rgba(0,0,0,1) 90%);
  background-repeat: no-repeat;
  background-attachment: fixed;
  filter: progid:DXImageTransform.Microsoft.gradient(startColorstr="#3c6eb4",endColorstr="#3c95b4",GradientType=1);
        color: white;
        font-size: 0.9em;
        font-weight: 400;
        font-family: 'Montserrat', sans-serif;
        margin: 0;
        padding: 10em 6em 10em 6em;
        box-sizing: border-box;

      }
    ...
```

Il n'affiche pas mon "Test Apache SELinux" donc il remet la page par défaut.
SELinux bloque car /srv/srv/srv_1 n’a pas le bon label de sécurité (httpd_sys_content_t).

### Utilisation de ``sealert``

On installe sealert avec le paquet setroubleshoot-server car il n’était pas présent par défaut.
Cet outil nous permet d’analyser les logs SELinux et d’obtenir une explication claire ainsi que les commandes à appliquer pour corriger les erreurs de contexte.

```
[telos@selinux html]$ sudo sealert -a /var/log/audit/audit.log
100% done
found 4 alerts in /var/log/audit/audit.log
--------------------------------------------------------------------------------

SELinux is preventing /usr/sbin/httpd from getattr access on the file /srv/srv/srv_1/index.html.

*****  Plugin catchall_labels (83.8 confidence) suggests   *******************

If you want to allow httpd to have getattr access on the index.html file
Then you need to change the label on /srv/srv/srv_1/index.html
Do
# semanage fcontext -a -t FILE_TYPE '/srv/srv/srv_1/index.html'
...
```

```
[telos@selinux html]$ sudo semanage fcontext -a -t httpd_sys_content_t "/srv/srv/srv_1(/.*)?"

[telos@selinux html]$ sudo restorecon -Rv /srv/srv/srv_1
Relabeled /srv/srv/srv_1 from unconfined_u:object_r:var_t:s0 to unconfined_u:object_r:httpd_sys_content_t:s0
Relabeled /srv/srv/srv_1/index.html from unconfined_u:object_r:var_t:s0 to unconfined_u:object_r:httpd_sys_content_t:s0
```

Pour permettre à Apache d’accéder au nouveau dossier /srv/srv/srv_1 en mode enforce, on utilise les commandes suivantes :

``semanage fcontext -a -t httpd_sys_content_t "/srv/srv/srv_1(/.*)?"``

Cette commande indique à SELinux que tous les fichiers du dossier /srv/srv/srv_1 doivent avoir le type httpd_sys_content_t, utilisé pour les contenus web lisibles par Apache.

``restorecon -Rv /srv/srv/srv_1``

Cette commande applique les nouveaux contextes définis par semanage aux fichiers déjà présents dans le dossier.

### Le service Apache est-il accessible une fois le profil corrigé et en mode enforce ?

```
[telos@selinux html]$ curl http://localhost
Test Apache SELinux
```

**Oui**, Apache fonctionne à nouveau.
Les fichiers ont désormais le bon contexte, et **SELinux** autorise l’accès.

# 3.5 Durcissement SELinux via CIS Benchmark

## 1. Téléchargement du CIS Benchmark

Le guide officiel de sécurité du Center for Internet Security (CIS) pour Rocky Linux 9 est disponible sur le site :

https://www.cisecurity.org/benchmark/rocky_linux

J’ai utilisé ce benchmark comme référence pour appliquer les bonnes pratiques de durcissement liées à SELinux.

---

## 2. Directives SELinux issues du CIS Benchmark

### a. Vérifier que SELinux est activé et en mode enforcing

Le résultat doit montrer que SELinux est activé et en mode enforcing.

```
[telos@selinux html]$ sudo sestatus
[sudo] password for telos:
SELinux status:                 enabled
SELinuxfs mount:                /sys/fs/selinux
SELinux root directory:         /etc/selinux
Loaded policy name:             targeted
Current mode:                   enforcing
Mode from config file:          enforcing
Policy MLS status:              enabled
Policy deny_unknown status:     allowed
Memory protection checking:     actual (secure)
Max kernel policy version:      33
```

---

### b. Vérifier la configuration dans le fichier principal

Contenu recommandé :

**SELINUX=enforcing**  
**SELINUXTYPE=targeted**

Cela garantit l'application stricte des politiques SELinux pour les services critiques.

```
[telos@selinux html]$ sudo cat /etc/selinux/config

# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
# See also:
# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/using_selinux/changing-selinux-states-and-modes_using-selinux#changing-selinux-modes-at-boot-time_changing-selinux-states-and-modes
#
# NOTE: Up to RHEL 8 release included, SELINUX=disabled would also
# fully disable SELinux during boot. If you need a system with SELinux
# fully disabled instead of SELinux running with no policy loaded, you
# need to pass selinux=0 to the kernel command line. You can use grubby
# to persistently set the bootloader to boot with selinux=0:
#
#    grubby --update-kernel ALL --args selinux=0
#
# To revert back to SELinux enabled:
#
#    grubby --update-kernel ALL --remove-args selinux
#
SELINUX=enforcing
# SELINUXTYPE= can take one of these three values:
#     targeted - Targeted processes are protected,
#     minimum - Modification of targeted policy. Only selected processes are protected.
#     mls - Multi Level Security protection.
SELINUXTYPE=targeted
```

---

### c. S'assurer qu’aucun service ne tourne en mode non confiné

Aucun service ne doit apparaître. Si c’est le cas, des règles supplémentaires doivent être appliquées ou le service doit être limité.

```
[telos@selinux html]$ sudo ps -eZ | grep unconfined_service_t
[telos@selinux html]$
```

---

## 3. Tests post-configuration

Après modification :

- On redémarre le service Apache.

```
[telos@selinux html]$ sudo systemctl restart httpd
```

- On accéde au site web depuis le navigateur ou curl : OK.

```
[telos@selinux html]$ curl http://localhost
Test Apache SELinux
```

- On vérifie les logs SELinux pour s’assurer qu’aucune alerte (AVC) ne bloquait le fonctionnement :

```
[telos@selinux html]$ sudo grep AVC /var/log/audit/audit.log
```

---

# 4. Remarques et constats

### Points de blocage rencontrés :
- Certaines notion de SeLinux peuvent être compliqué à comprendre surtout les contextes

---

### Ce que j’ai appris :
- Les bases de SELinux, notamment ses différents modes de fonctionnement (enforcing, permissive), les types de contextes et les politiques de sécurité associées.
- Comment appliquer les recommandations du CIS Benchmark pour renforcer la sécurité du système, tout en veillant à ne pas perturber les services existants.

---

# 5. Conclusion

Récapitulatif des protections mises en place :
- SSH durci
- Firewall actif et restrictif
- Apache fonctionnel avec SELinux enforce
- Contextes SELinux adaptés manuellement
- Durcissement conforme à des recommandations reconnues (ANSSI/CIS)