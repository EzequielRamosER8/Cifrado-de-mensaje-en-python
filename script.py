import tkinter as tk
from tkinter import simpledialog, messagebox
import json
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib

# XOR helper
def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Guardar mensaje
def guardar_mensaje(mensaje, contrasena):
    salt = get_random_bytes(16)
    clave = PBKDF2(contrasena, salt, dkLen=32, count=100000)
    mensaje_bytes = mensaje.encode()
    mensaje_xor = xor_encrypt(mensaje_bytes, clave)
    iv = get_random_bytes(16)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    relleno = AES.block_size - len(mensaje_xor) % AES.block_size
    mensaje_xor += bytes([relleno]) * relleno
    cifrado = cipher.encrypt(mensaje_xor)
    return {
        'salt': salt.hex(),
        'iv': iv.hex(),
        'mensaje_cifrado': cifrado.hex()
    }

# Leer mensaje
def leer_mensaje(datos, contrasena):
    salt = bytes.fromhex(datos['salt'])
    iv = bytes.fromhex(datos['iv'])
    mensaje_cifrado = bytes.fromhex(datos['mensaje_cifrado'])
    clave = PBKDF2(contrasena, salt, dkLen=32, count=100000)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    mensaje_xor = cipher.decrypt(mensaje_cifrado)
    relleno = mensaje_xor[-1]
    mensaje_xor = mensaje_xor[:-relleno]
    mensaje_descifrado = xor_encrypt(mensaje_xor, clave).decode()
    return mensaje_descifrado

# Funciones para GUI
def guardar_mensaje_tk(mensaje, contrasena):
    datos = guardar_mensaje(mensaje, contrasena)
    with open("mensaje_tk.json", 'w') as f:
        json.dump(datos, f)
    messagebox.showinfo("Éxito", "Mensaje cifrado guardado.")

def leer_mensaje_tk(contrasena):
    try:
        with open("mensaje_tk.json", 'r') as f:
            datos = json.load(f)
        mensaje = leer_mensaje(datos, contrasena)
        messagebox.showinfo("Mensaje Descifrado", mensaje)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo descifrar: {e}")

# Crear ventana principal
ventana = tk.Tk()
ventana.title("Cifrador de Mensajes")
ventana.geometry("300x200")

def opcion_guardar():
    mensaje = simpledialog.askstring("Mensaje", "Escribí el mensaje a cifrar:")
    if mensaje:
        contrasena = simpledialog.askstring("Contraseña", "Ingresá una contraseña:", show='*')
        if contrasena:
            guardar_mensaje_tk(mensaje, contrasena)

def opcion_leer():
    contrasena = simpledialog.askstring("Contraseña", "Ingresá la contraseña para descifrar:", show='*')
    if contrasena:
        leer_mensaje_tk(contrasena)

# Botones
btn_guardar = tk.Button(ventana, text="Guardar Mensaje", command=opcion_guardar)
btn_guardar.pack(pady=20)

btn_leer = tk.Button(ventana, text="Leer Mensaje", command=opcion_leer)
btn_leer.pack(pady=10)

# Ejecutar ventana
ventana.mainloop()


