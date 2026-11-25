# Image Python officielle, variante "slim" (Debian allégée)
FROM python:3.12-slim

# Pas de fichiers .pyc et logs affichés immédiatement (utile pour docker logs)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Répertoire de travail dans l'image
WORKDIR /app

# On copie d'abord requirements.txt pour profiter du cache Docker
COPY requirements.txt .

# Installation des dépendances (Flask, gunicorn...) sans garder le cache pip
RUN pip install --no-cache-dir -r requirements.txt

# On copie ensuite le code de l'application
COPY app.py .
COPY templates ./templates

# Bonne pratique : ne pas faire tourner l'application en root
RUN useradd --create-home appuser
USER appuser

# gunicorn écoutera sur le port 5000 dans le conteneur
EXPOSE 5000

# Serveur de production gunicorn (au lieu de "python app.py", réservé au développement)
# "app:app" = fichier app.py, objet Flask nommé app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
