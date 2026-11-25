#!/usr/bin/env bash
# Mission 4 - partie qui demande un compte Docker (registre dhi.io)
# A lancer depuis Git Bash, dans le dossier dockerfile-exercice2/dhi :
#   docker login dhi.io      (identifiant Docker + mot de passe ou jeton d'accès)
#   bash dhi-commandes.sh
set -e
export MSYS_NO_PATHCONV=1
mkdir -p resultats

# 1. Les deux variantes de l'image DHI
docker pull dhi.io/node:22-alpine3.23
docker pull dhi.io/node:22-alpine3.23-dev
docker image inspect dhi.io/node:22-alpine3.23 \
  --format 'runtime: entrypoint={{json .Config.Entrypoint}} cmd={{json .Config.Cmd}} user={{.Config.User}}' \
  | tee resultats/03-dhi-variantes.txt
docker image inspect dhi.io/node:22-alpine3.23-dev \
  --format 'dev: user={{.Config.User}}' | tee -a resultats/03-dhi-variantes.txt

# 2. Build de l'appli avec le Dockerfile DHI
docker build -f my-app/Dockerfile.dhi -t my-app:1.1 my-app

# 3. Vérifications : ça marche, pas de shell, pas root
docker rm -f my-app-1.1 2>/dev/null || true
docker run -d --name my-app-1.1 -p 3000:3000 my-app:1.1
sleep 3
{
  echo "## my-app:1.1 (Docker Hardened Image)"
  curl -s http://localhost:3000/; echo
  docker images my-app:1.1
  docker image inspect my-app:1.1 -f 'User={{.Config.User}}'
  echo "## Shell present ?"
  docker exec my-app-1.1 sh -c 'echo oui' 2>&1 || true
  echo "## npm present ?"
  docker exec my-app-1.1 npm --version 2>&1 || true
} | tee resultats/04-my-app-1.1-etat.txt
docker rm -f my-app-1.1

# 4. Scan de vulnérabilités (Trivy, sans monter le socket Docker)
docker save my-app:1.1 -o my-app-1.1.tar
docker run --rm -v trivy-cache:/root/.cache -v "$(pwd -W 2>/dev/null || pwd)":/scan:ro aquasec/trivy:0.69.1 \
  image --input /scan/my-app-1.1.tar --scanners vuln --quiet > resultats/05-my-app-1.1-trivy.txt 2>&1
rm -f my-app-1.1.tar
grep -E "Total" resultats/05-my-app-1.1-trivy.txt

# 5. (Optionnel) Docker Scout : comparaison et attestations DHI
#    docker login   (Docker Hub)
#    docker scout quickview my-app:1.1
#    docker scout compare my-app:1.1 --to my-app:1.0 --ignore-unchanged
#    docker scout attest list registry://dhi.io/node:22-alpine3.23
