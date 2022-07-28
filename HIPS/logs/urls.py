from django.conf import settings
from django.urls import include,path
from logs.views import home, mensajes_off, settings_logs, usuarios_conectados, validacion_off, verificar_directorios

urlpatterns = [
   # path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('Settings', settings_logs, name='Settings'),
    path('verificar_directorios', verificar_directorios, name='Verificar Directorios'),
    path('usuarios_conectados', usuarios_conectados, name='Usuarios Conectados'),
    path('validacion_off', validacion_off, name='Validacion Off'),
    path('mensajes_off', mensajes_off, name='Mensajes Off'),
]

