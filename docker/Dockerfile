# WebMap
# -
# https://github.com/SabyasachiRana/WebMap
# Author: SabyasachiRana
# -
# Usage:
#   $ cd /opt
#   $ git clone https://github.com/SabyasachiRana/WebMap.git
#   $ cd WebMap/docker
#   $ docker build -t webmap:latest .
#   $ docker run -d -v /opt/WebMap/docker/xml:/opt/xml -p 8000:8000 webmap:latest
#
# Nmap Example:
#   $ nmap -sT -A -oX /tmp/myscan.xml 192.168.1.0/24
#   $ mv /tmp/myscan.xml /opt/WebMap/docker/xml
#
# Now you can point your browser to http://localhost:8000


FROM ubuntu:latest

# Variables d'environnement
ENV DEBIAN_FRONTEND=noninteractive \
    WKHTMLTOPDF_VERSION=0.12.4

# Installation des dépendances et configuration initiale
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip curl wget git wkhtmltopdf libssl-dev tzdata nmap \
    && mkdir -p /opt/xml /opt/notes \
    && wget -P /opt/ https://github.com/wkhtmltopdf/wkhtmltopdf/releases/download/${WKHTMLTOPDF_VERSION}/wkhtmltox-${WKHTMLTOPDF_VERSION}_linux-generic-amd64.tar.xz \
    && tar -xvf /opt/wkhtmltox-${WKHTMLTOPDF_VERSION}_linux-generic-amd64.tar.xz -C /opt/ \
    && rm -f /opt/wkhtmltox-${WKHTMLTOPDF_VERSION}_linux-generic-amd64.tar.xz \
    && pip3 install --no-cache-dir Django requests xmltodict \
    && cd /opt/ && django-admin startproject nmapdashboard \
    && cd /opt/nmapdashboard && git clone https://github.com/SabyasachiRana/WebMap.git nmapreport \
    && cd nmapreport && git checkout master \
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copie de tous les fichiers nécessaires depuis le répertoire docker
COPY docker /tmp/docker

# Déplacement des fichiers vers leurs emplacements finaux
RUN mv /tmp/docker/settings.py /opt/nmapdashboard/nmapdashboard/settings.py \
    && mv /tmp/docker/urls.py /opt/nmapdashboard/nmapdashboard/urls.py \
    && mv /tmp/docker/tzdata.sh /root/tzdata.sh \
    && mv /tmp/docker/startup.sh /startup.sh \
    && rm -rf /tmp/docker

# Finalisation de la configuration
RUN cd /opt/nmapdashboard && python3 manage.py migrate \
    && ln -s /opt/nmapdashboard/nmapreport/token.py /root/token \
    && chmod +x /root/tzdata.sh /startup.sh /root/token

# Exposition du port
EXPOSE 8000

# Point d'entrée
ENTRYPOINT ["bash", "/startup.sh"]
