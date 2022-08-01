from django.conf import settings
from django.urls import include,path
from logs.views import access_log, home, mensajes_off, salir, settings_logs, usuarios_conectados, validacion_off, verificar_directorios, access_log, masivos_mail,verificar_tmp, ddos_dns, salir
urlpatterns = [
   # path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('Settings', settings_logs, name='Settings'),
    path('verificar_directorios', verificar_directorios, name='Verificar Directorios'),
    path('usuarios_conectados', usuarios_conectados, name='Usuarios Conectados'),
    path('validacion_off', validacion_off, name='Validacion Off'),
    path('mensajes_off', mensajes_off, name='Mensajes Off'),
    path('access_log', access_log, name='Access Log'),
    path('masivos_mail', masivos_mail, name='Masivos Mail'),
    path('verificar_tmp', verificar_tmp, name='Verificar los Scripts'),
    path('ddos_dns', ddos_dns, name='Verificar ataque DDOS'),
    path('salir', salir, name='Salir'),
]

