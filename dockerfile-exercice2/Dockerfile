# =====================================================================
#  Dockerfile sécurisé - Quiz Docker (application Vite)
#  Build multi-étapes : Node sert à COMPILER, Nginx sert à DIFFUSER.
#
#  Build : docker build -t quiz-docker:secure .
#  Run   : docker compose up -d   (voir docker-compose.yml)
# =====================================================================

# ---------- Étape 1 : construction (build) ----------
# Tag précis (version Node + version Alpine) + digest : le build est reproductible
# et personne ne peut remplacer l'image derrière le tag sans qu'on s'en apercoive.
# Node 24 = version LTS maintenue (Node 18 de la version initiale n'a plus de correctifs).
FROM node:24.22.3-alpine3.24@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5 AS build

WORKDIR /app

# Dépendances d'abord, pour profiter du cache Docker
COPY package.json package-lock.json ./

# npm ci : installe exactement les versions du package-lock.json
RUN npm ci

# Code source (filtré par .dockerignore). COPY et pas ADD : ADD sait aussi
# télécharger des URL et décompresser des archives, ce qu'on ne veut pas ici.
COPY . .

# Génère les fichiers statiques dans /app/dist
RUN npm run build


# ---------- Étape 2 : nettoyage du serveur web ----------
# nginx-unprivileged : variante officielle de Nginx prévue pour tourner SANS root
# (utilisateur nginx uid 101, port 8080, fichiers temporaires dans /tmp).
# Version 1.31.7 (branche "mainline", celle que nginx.org recommande) sur Alpine 3.24,
# épinglée par tag précis + digest. La 1.30.6 "stable" avait 4 CVE critiques non
# encore corrigées dans une image publiée au moment du TP.
FROM nginxinc/nginx-unprivileged:1.31.7-alpine3.24@sha256:b5047b9b76845eac124358373c6852377c52e4b05834a47647e955dd91cb8f1e AS web

# root seulement dans cette étape intermédiaire (elle ne part pas en production) :
#  - apk upgrade : applique les derniers correctifs de sécurité Alpine
#  - apk del : supprime ce qui ne sert pas pour des fichiers statiques
#    (curl, modules nginx image-filter / xslt / geoip / njs et leurs librairies)
#  - suppression du binaire apk : plus de gestionnaire de paquets dans le conteneur
#    (la base /lib/apk/db est gardée exprès pour que les scanners de CVE marchent)
USER root
RUN apk upgrade --no-cache \
 && apk del --no-cache curl nginx-module-image-filter nginx-module-xslt nginx-module-geoip nginx-module-njs \
 && rm -f /sbin/apk \
 && rm -rf /etc/apk/cache /var/cache/apk/*

# On récupère QUE le résultat du build : ni Node, ni node_modules, ni code source.
# Les fichiers appartiennent à root : nginx peut les lire mais pas les modifier.
COPY --from=build /app/dist /usr/share/nginx/html


# ---------- Étape 3 : image finale (production) ----------
# Supprimer des fichiers dans un RUN ne fait que les masquer : ils restent dans
# les couches du dessous et l'image ne maigrit pas. On repart donc de "scratch"
# (image vide) et on copie le système déjà nettoyé : une seule couche, sans les
# fichiers supprimés.
FROM scratch

COPY --from=web / /

LABEL org.opencontainers.image.title="quiz-docker" \
      org.opencontainers.image.description="Quiz Docker (Vite) servi par Nginx non-root"

# "scratch" ne connait rien de l'image nginx : on redonne les réglages utiles
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]

# Utilisateur non-root (uid:gid numériques)
USER 101:101

# Port interne (un utilisateur non-root ne peut pas écouter sur 80)
EXPOSE 8080

# Docker vérifie que le site répond ; sinon le conteneur passe "unhealthy"
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8080/ || exit 1

# Pas de CMD : celui de l'image de base ("nginx -g 'daemon off;'") convient
