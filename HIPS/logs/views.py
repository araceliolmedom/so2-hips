import os
from typing import Tuple
from django.http import HttpResponse
from django.shortcuts import render
import subprocess
from requests import request
from logs.models import CheckSuma
import string
import random
import datetime as dt
import sys
from django.contrib import messages

# Create your views here.
def home(request):
    return render(request, 'index.html')

def settings_logs(request):
    Nombre='Configuracion Inicial'
    programas = []
    binarios  = ['/etc/passwd','/etc/shadow','/etc/group']
    for archivo in binarios:
        h = os.popen(f"md5sum {archivo}").read()
        c = CheckSuma(directorio = archivo , hashsuma = h )
        c.save()
    return render (request, 'resultados.html', {'Nombre':Nombre})


'''
    Verifica si los archivos binarios del sistema han sido modificados
    Los compara con los hash que estan almacenados en la base de datos
'''
def verificar_directorios(request):
    modificado = True
    listamsg= []
    Nombre='Verificar Directorios'
    for hash in CheckSuma.objects.raw('SELECT id,directorio,hashsuma FROM logs_checksuma'):
        aux = os.popen(f"md5sum {hash.directorio}").read()
        print(aux)
        #Si los hash coinciden no hubo modificacion en el archivo
        if aux == hash.hashsuma:
            print(aux)
            print(hash.hashsuma)

            modificado = False
            msg = 'No se modifico el directorio : ' + hash.directorio
            messages.add_message(request, messages.INFO,msg)
        else:
            if aux != '':
                msg = 'Se modifico el directorio : ' + hash.directorio
                messages.add_message(request, messages.INFO,msg)
               
        
    if modificado:

        msg = "No se modifico ningun directorio "
        messages.add_message(request, messages.INFO,msg)

                
    return render (request, 'resultados.html', {'Nombre':Nombre})


'''
    Para saber quienes son los usuarios conectados y desde donde.
    Ejecutamos el comando w
'''
def usuarios_conectados(request):
    Nombre='Usuarios Conectados'
    listamsg = []

    try:
        #El retorno es de tipo bytes y no str
        cmd = subprocess.check_output("w", shell=True).decode('utf-8') 
        lista_usuarios = cmd.split('\n')
        #Eliminamos la cabezera del comando
        lista_usuarios.pop(0)
        #Eliminamos el ultimo valor de la lista
        lista_usuarios.pop(-1)
        msg = "Usuario------From:"
        messages.add_message(request, messages.INFO,msg)
        for linea in lista_usuarios:
            usuario = linea.split()[0]
            desde   = linea.split()[3]
            listamsg.append(usuario + "-----" + desde)
            print (lista_usuarios)

    except Exception:
       msg = "No se pudo mostrar los usuarios conectados"
       messages.add_message(request, messages.INFO,msg)
    return render (request, 'resultados.html', {'Nombre':Nombre})


'''
    Verificamos en el archivo secure los  intentos fallidos de autenticacion 
    En el caso la cantidad supere 10 intentos,se procede a bloquear temporalmente a ese usuario
'''

def validacion_off(request):
    Nombre='Fallo de Autenticacion'   
    listamsg = []
    cmd = "sudo cat  /var/log/secure | grep -i 'authentication failure'"
    resultado_cmd = os.popen(cmd).read().split("\n")
    resultado_cmd.pop(-1)

    usuarios_contador = {}

    # Recorremos cada linea de alerta
    for linea in resultado_cmd:
        linea  = linea.split()
        usuario = linea[14].split("=")[1]
        # Si ya esta incializado un contador para el usuario , entonces procedemos, sino, inicializamos
        if usuario in usuarios_contador:
            #si existe le sumamos uno al contador de failure en ese usuario

            usuarios_contador[usuario] = usuarios_contador[usuario] + 1 
           
            # Si el contador de failure del usuario supera un limite, es una alarma,
            
            if usuarios_contador[usuario] == 10:
                msg = f"El usuario : {usuario} fue bloqueado"
                messages.add_message(request, messages.INFO,msg)
                #procedemos a bloquear al usario
                msg = f"Demasiados intentos fallidos de iniciar seccion"
                messages.add_message(request, messages.INFO,msg)
        else:
            usuarios_contador[usuario] = 1
        
    return render (request, 'resultados.html', {'Nombre':Nombre})



def mensajes_off(request):
    band=False
    Nombre='Messages SMTP'
    cmd = "sudo cat /var/log/messages | grep -i 'service=smtp' | grep -i 'auth failure'"
    resultado_cmd = os.popen(cmd).read().split("\n")
    resultado_cmd.pop(-1)

    usuarios_contador = {}

    # Recorremos cada linea de alerta
    for linea in resultado_cmd:
        linea  = linea.split()
        usuario = linea[9].split("=")[1][:-1]
        
        # Si ya esta incializado un contador para el usuario en username, entonces procedemos, sino, inicializamos
        if usuario in usuarios_contador:
            usuarios_contador[usuario] = usuarios_contador[usuario] + 1 # si existe le sumamos uno al contador de failure en ese usuario
            # Si el contador de failure del usuario supera un limite, es una alarma, procedemos a cambiar la contrasenha
            if usuarios_contador[usuario] == 50:
                band=True
                msg = f"El usuario : {usuario} fue bloqueado"
                messages.add_message(request, messages.INFO,msg)
                #procedemos a bloquar al usuario

                msg = f"Muchas entradas de auth failure de stmp en el archivo /var/log/messages"
                messages.add_message(request, messages.INFO,msg)
               
        else:
            usuarios_contador[usuario] = 1
    if band==False:
        msg = "No se registraron ataques SMTP "
        messages.add_message(request, messages.INFO,msg)
    return render (request, 'resultados.html', {'Nombre':Nombre})

'''
    Verifica archivo access.log y bloquea todas las ip cuyas solititudes terminen en 404 {page not found}

    cat                         =
    /var/log/httpd/access.log   =
    | grep -i 'HTTP'            =
    | grep -i '404'             =
'''
def access_log(request):
    Nombre='Access log'
    cmd = "sudo cat /var/log/httpd/access.log | grep -i 'HTTP' | grep -i '404'"
    resultado_cmd = os.popen(cmd).read().split('\n')
    resultado_cmd.pop(-1)

    contador_ip = {}

    for linea in resultado_cmd:
        ip =  linea.split()[0]
        
        if ip in contador_ip:
            contador_ip[ip] = contador_ip[ip] + 1
            if contador_ip[ip] == 5:
                msg = f"{ip} : bloqueada muchos respuestas 404 desde esta IP "
                messages.add_message(request, messages.INFO,msg)
                
                # bloqueamos la ip
               # bloquear_ip(ip)  
                
        else:
            contador_ip[ip] = 1

    return render (request, 'resultados.html', {'Nombre':Nombre})


'''
    Verifica archivo access.log y bloquea todas las ip cuyas solititudes terminen en 404 {page not found}

    cat                         =
    /var/log/httpd/access.log   =
    | grep -i 'HTTP'            =
    | grep -i '404'             =
'''
def masivos_mail(request):
    Nombre='Mail Masivos'
    cmd = "sudo cat /var/log/maillog | grep -i 'authid' "
    resultado_cmd = os.popen(cmd).read().split('\n')
    resultado_cmd.pop(-1)

    contador_email = {}

    for linea in resultado_cmd:
        authid = [word for word in linea.split() if 'authid=' in word][0]
        email = authid.split("=")[-1][:-1]
        if email in contador_email:
            # Incrementamos el contador de cuantos email lleva este email
            contador_email[email] = contador_email[email] + 1
            # Si el email envio mas de 50 mails, lo consideramos masivos
            if contador_email[email] == 50:  
                
                #bloquear_email(email)
                msg = f"El email : {email} fue bloqueado "
                messages.add_message(request, messages.INFO,msg)
                msg = f"Demasiados mail enviados desde un mismo email"
                messages.add_message(request, messages.INFO,msg)
            
        else:
            contador_email[email] = 1

    return render (request, 'resultados.html', {'Nombre':Nombre})
    

# Verificamos si hay archivos en /tmp que contengan al comienzo #!
def verificar_tmp(request):
    Nombre='Verificar TMP'
    # buscamos en el directorio tmp los archivos, y solo queremos lo que son archivos y no directorios (type -f)
    command = f"sudo find /tmp 2>/dev/null -type f" 
    archivos = os.popen(command).read().split()
    
    archivos_a_cuarentena = []
    # Procedemos a verificar los archivos
    for archivo in archivos:
        new_diccionary = {}
        
        # Si el archivo es un py, cpp, c, exe, sh, ruby, php, entra en el if
        if any(substring in archivo for substring in [".cpp", ".py", ".c", ".exe", ".sh", ".ruby", ".php"]):
            new_diccionary['ruta_archivo'] = archivo
            new_diccionary['ruta_a_mover'] = "/cuarentena/tmp_scripts/" + archivo[1:].replace("/", "-")
            new_diccionary['motivo'] = "Es un archivo tipo con extension sospechosa (.py .sh etc)"
            archivos_a_cuarentena.append(new_diccionary)
            msg =  f"\nSe encontro un archivo de tipo script {new_diccionary['ruta_archivo']} (#! primera linea), se movio a cuarentena\n"
            messages.add_message(request, messages.INFO,msg)
            #cuerpo_email = cuerpo_email + f"\nSe encontro el archivo {new_diccionary['ruta_archivo']} con extension sospechosa (.py, .sh, etc), se envio a cuarentena.\n"
            
        else: 
            # Si no, busca si el archivo tiene un #! en la primera linea, lo cual significa que es un archivo script
            try:     
                with open(f"{archivo}", "r") as f:
                    primera_linea = f.readline() # Leemos la primera linea del archivo
                    if "#!" in primera_linea:
                        new_diccionary['ruta_archivo'] = archivo
                        new_diccionary['ruta_a_mover'] = "/cuarentena/tmp_scripts/" + archivo[1:].replace("/", "-")
                        new_diccionary['motivo'] = "Es un archivo tipo script (#!)"
                        archivos_a_cuarentena.append(new_diccionary)
                        msg =  f"\nSe encontro un archivo de tipo script {new_diccionary['ruta_archivo']} (#! primera linea), se movio a cuarentena\n"
                        messages.add_message(request, messages.INFO,msg)

            except Exception:
                print("El archivo esta codeado en bytes")
        
    for archivo in archivos_a_cuarentena:
        try:
            os.system(f"sudo mv {archivo['ruta_archivo']} {archivo['ruta_a_mover']}")
        except Exception:
            print(f"No se pudo mover a cuarentena el archivo: {archivo}.")
    


    #Procedemos a escribir en el archivo
    if archivos_a_cuarentena:    
        msg = "Ya se movio los ultimos archivos"
    else:
        msg = "No se encontro archivos sospechosos en /tmp/"
        messages.add_message(request, messages.INFO,msg)
   
    return render (request, 'resultados.html', {'Nombre':Nombre})
   

def ddos_dns(request):
    band=False
    Nombre='Verificar ataque DDOS'
    dns_file_log = os.popen("sudo cat /tcpdump_dns").read().split('\n')
    dns_file_log.pop(-1)

    ip_contador = {}

    for elemento_linea in dns_file_log:
        ip_atacante = elemento_linea.split()[2]
        ip_destino = elemento_linea.split()[4][:-1] # [:-1] para borrar el : final

        if (ip_atacante, ip_destino) in ip_contador:
            ip_contador[(ip_atacante, ip_destino)] = ip_contador[(ip_atacante, ip_destino)] + 1
            msg = f"IP : {ip_atacante} bloqueada posible ataque DDOS"
            messages.add_message(request, messages.INFO,msg)
            # Si hubieron al menos 10 ip atacante a un mismo ip destino, entonces es alarmante y tomamos una accion
            if ip_contador[(ip_atacante, ip_destino)] == 10:
                band=True           
                # Le damos formato para que acepte iptables
                ip_atacante_iptables = ip_atacante.split('.')[:-1]
                ip_atacante_iptables = f"{ip_atacante_iptables[0]}.{ip_atacante_iptables[1]}.{ip_atacante_iptables[2]}.{ip_atacante_iptables[3]}"
               
                

        else:
            ip_contador[(ip_atacante, ip_destino)] = 1
    if band==False:
        msg = "No se registraron ataques DDOS"
    return render (request, 'resultados.html', {'Nombre':Nombre})