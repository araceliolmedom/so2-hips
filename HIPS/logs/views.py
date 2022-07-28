import os
from django.http import HttpResponse
from django.shortcuts import render
import subprocess
from requests import request
from logs.models import CheckSuma
import string
import random
import datetime as dt
import sys

# Create your views here.
def home(request):
    return render(request, 'index.html')

def settings_logs(request):
    programas = []
    binarios  = ['/etc/passwd','/etc/shadow','/etc/group']
    for archivo in binarios:
        h = os.popen(f"md5sum {archivo}").read()
        c = CheckSuma(directorio = archivo , hashsuma = h )
        c.save()
    return HttpResponse ('La configuracion fue exitosa')


'''
    Verifica si los archivos binarios del sistema han sido modificados
    Los compara con los hash que estan almacenados en la base de datos
'''
def verificar_directorios(request):
    modificado = True
    listamsg= []

    for hash in CheckSuma.objects.raw('SELECT id,directorio,hashsuma FROM logs_checksuma'):
        aux = os.popen(f"md5sum {hash.directorio}").read()
        print(aux)
        #Si los hash coinciden no hubo modificacion en el archivo
        if aux == hash.hashsuma:
            print(aux)
            print(hash.hashsuma)

            modificado = False
            msg = 'No se modifico el directorio : ' + hash.directorio
            listamsg.append(msg)
        else:
            if aux != '':
                msg = 'Se modifico el directorio : ' + hash.directorio
                listamsg.append(msg)
                ''' tipo_alerta = "Alerta"
                asunto      = "Modificacion de archivos binarios!"
                cuerpo      =  tipo_alerta + ' : ' + msg
                func_enviar_mail(asunto,cuerpo)'''
        
    if modificado:

        msg = "No se modifico ningun directorio "
        listamsg.append(msg)

                
    return HttpResponse (listamsg)


'''
    Para saber quienes son los usuarios conectados y desde donde.
    Ejecutamos el comando w
'''
def usuarios_conectados(request):

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
        listamsg.append(msg)
        for linea in lista_usuarios:
            usuario = linea.split()[0]
            desde   = linea.split()[3]
            listamsg.append(usuario + "-----" + desde)
            print (lista_usuarios)

    except Exception:
       msg = "No se pudo mostrar los usuarios conectados"
       listamsg.append(msg)
    return HttpResponse(listamsg)


'''
    Verificamos en el archivo secure los  intentos fallidos de autenticacion 
    En el caso la cantidad supere 10 intentos,se procede a bloquear temporalmente a ese usuario
'''

def validacion_off(request):
   
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
                listamsg.append(msg)
                #procedemos a bloquear al usario
                '''  bloquear_usuario(usuario)
                tipo_alerta = "PREVENCION"
                asunto      = "AUTENTICACION FALLIDA!"
                cuerpo      =  tipo_alerta + ' : ' + msg
                func_enviar_mail(asunto,cuerpo)
                escribir_log(alarmas_o_prevencion='prevencion',
                            tipo_alarma='su:auth_ATTACK',
                            ip_o_email=usuario,
                            motivo='Muchas entradas de auth failure por su:auth por el ruser, se se bloqueo el usuario'
                            )
                '''           
                msg = f"Demasiados intentos fallidos de iniciar seccion"
                listamsg.append(msg)
        else:
            usuarios_contador[usuario] = 1
        
    return HttpResponse(listamsg)



def mensajes_off(request):
    listamsg = []
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
                msg = f"El usuario : {usuario} fue bloqueado"
                listamsg.append(msg)
                #procedemos a bloquar al usuario
                '''bloquear_usuario(usuario)

                msg = f"El usuario : {usuario} fue bloqueado"
                listamsg.append(msg)
                tipo_alerta = "PREVENCION"
                asunto      = "Ataque SMTP!"
                cuerpo      =  tipo_alerta + ' : ' + msg
                func_enviar_mail(asunto,cuerpo)
                escribir_log(
                            alarmas_o_prevencion='prevencion',
                            tipo_alarma='Auth ATTACK', ip_o_email=usuario,
                            motivo='Muchas entradas de auth failure de stmp en el usuario, se cambio la contrasenha'
                            )'''
                msg = f"Muchas entradas de auth failure de stmp en el archivo /var/log/messages"
                listamsg.append(msg)
               
        else:
            usuarios_contador[usuario] = 1
    if len(listamsg) is None :
        msg = "No se registraron ataques SMTP "
        listamsg.append(msg)
    return HttpResponse(listamsg)
        
