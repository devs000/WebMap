from django.contrib import admin
from django.urls import include, path

# Définition des routes (URLs) principales de l'application
urlpatterns = [
    # Route principale : Redirige toutes les requêtes vers l'application `nmapreport`
    path('', include('nmapreport.urls')),
    # ^ Cette route gère la page d'accueil et redirige vers les URLs définies dans `nmapreport.urls`.
	
    # Route spécifique pour les rapports : Redirige également vers `nmapreport.urls`
    path('report/', include('nmapreport.urls')),
    # ^ Cette route permet d'accéder aux fonctionnalités de rapport via `/report/`.

    # Route pour l'interface d'administration Django
    path('admin/', admin.site.urls),
    # ^ Cette route active l'interface d'administration Django, accessible via `/admin/`.
]
