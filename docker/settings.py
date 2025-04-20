import os

# Chemins de base du projet
# Utilisez cette méthode pour construire des chemins dans le projet.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Paramètres de développement rapide - NON adaptés pour la production
# Référez-vous à https://docs.djangoproject.com/en/2.1/howto/deployment/checklist/
# pour une liste complète des paramètres de sécurité.

# AVERTISSEMENT DE SÉCURITÉ : Conservez la clé secrète utilisée en production confidentielle !
SECRET_KEY = 'rev3rse-notes:_you_should-change_this..._but_webmap_should_run_on_localhost_only..._so_no_problem_here.'
# ^^^ Cette clé n'est pas sécurisée pour la production. 
#     Elle ne doit être utilisée que pour un environnement local ou de test.

# AVERTISSEMENT DE SÉCURITÉ : N'exécutez pas avec DEBUG activé en production !
DEBUG = True
#       ^^^ Activez DEBUG uniquement pour le développement. 
#           En production, désactivez-le pour éviter d'exposer des informations sensibles.

ALLOWED_HOSTS = ['*']
#               ^ Permettre tous les hôtes peut être dangereux.
#                 Si vous déployez sur un serveur, limitez les hôtes autorisés.

# Définition des applications installées
INSTALLED_APPS = [
    'django.contrib.admin',  # Interface d'administration Django
    'django.contrib.auth',   # Authentification et gestion des utilisateurs
    'django.contrib.contenttypes',  # Framework de types de contenu
    'django.contrib.sessions',      # Gestion des sessions
    'django.contrib.messages',      # Messages flash pour les utilisateurs
    'django.contrib.staticfiles',   # Gestion des fichiers statiques
    'nmapreport',                   # Application principale pour les rapports Nmap
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',        # Sécurité HTTP (headers, etc.)
    'django.contrib.sessions.middleware.SessionMiddleware', # Gestion des sessions
    'django.middleware.common.CommonMiddleware',            # Middleware commun (redirections, etc.)
    'django.middleware.csrf.CsrfViewMiddleware',            # Protection CSRF
    'django.contrib.auth.middleware.AuthenticationMiddleware', # Authentification des utilisateurs
    'django.contrib.messages.middleware.MessageMiddleware', # Messages flash
    'django.middleware.clickjacking.XFrameOptionsMiddleware',# Protection contre le clickjacking
]

ROOT_URLCONF = 'nmapdashboard.urls'  # Point d'entrée principal pour les URL

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',  # Moteur de templates par défaut
        'DIRS': [],                                                    # Dossiers supplémentaires pour les templates
        'APP_DIRS': True,                                              # Recherche automatique des templates dans les apps
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',            # Variables de debug
                'django.template.context_processors.request',          # Données de la requête
                'django.contrib.auth.context_processors.auth',         # Contexte d'authentification
                'django.contrib.messages.context_processors.messages', # Messages flash
            ],
        },
    },
]

WSGI_APPLICATION = 'nmapdashboard.wsgi.application'  # Point d'entrée WSGI

# Configuration de la base de données
# https://docs.djangoproject.com/en/2.1/ref/settings/#databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Utilisation de SQLite pour la simplicité
        'NAME': '/opt/nmapdashboard/db.sqlite3', # Chemin vers la base de données SQLite
    }
}

# Validation des mots de passe
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',  # Évite les mots de passe similaires aux attributs de l'utilisateur
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',           # Longueur minimale des mots de passe
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',          # Évite les mots de passe courants
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',         # Évite les mots de passe purement numériques
    },
]

# Internationalisation
# https://docs.djangoproject.com/en/2.1/topics/i18n/
LANGUAGE_CODE = 'en-us'  # Code de langue par défaut
TIME_ZONE = 'UTC'        # Fuseau horaire par défaut
USE_I18N = True          # Activer la traduction internationale
USE_L10N = True          # Activer la localisation des formats de date et nombre
USE_TZ = True            # Utiliser les fuseaux horaires

# Fichiers statiques (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.1/howto/static-files/
STATIC_URL = '/static/'  # URL publique pour les fichiers statiques
