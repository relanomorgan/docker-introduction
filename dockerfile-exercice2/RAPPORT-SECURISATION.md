# TP – Sécurisation d'une image et d'un conteneur Docker (quiz-docker)

Application : le quiz Docker de `dockerfile-exercice2` (app Vite, fichiers statiques servis par Nginx).
Analyses faites le 25/11/2026. Les chiffres de CVE dépendent de la date du scan : la base de vulnérabilités change tous les jours.

## Fichiers rendus

| Fichier | Rôle |
|---|---|
| `Dockerfile.initial` | Dockerfile de départ (avant sécurisation) |
| `Dockerfile` | Dockerfile sécurisé |
| `.dockerignore` | fichiers exclus du build |
| `docker-compose.yml` | lancement du conteneur avec les restrictions (ressources, privilèges…) |
| `audit/initial/` | résultats de l'audit de `quiz-docker:initial` |
| `audit/secure/` | mêmes analyses sur `quiz-docker:secure` |
| `dhi/` | mission 4 : atelier Docker Hardened Images |

Outil de scan : **Trivy 0.69.1** (`aquasec/trivy`). J'ai pas utilisé Docker Scout car il faut être connecté à un compte Docker Hub. Pour scanner sans donner au scanner l'accès au socket Docker, j'exporte l'image avec `docker save` et Trivy lit le fichier `.tar`.

---

## Mission 1 – Audit de l'image initiale

### Ce que j'ai fait

```bash
docker build -f Dockerfile.initial -t quiz-docker:initial .
docker run -d --name quiz-initial -p 8083:80 quiz-docker:initial
curl -s -o /dev/null -w "%{http_code}" http://localhost:8083         # 200
docker exec quiz-initial cat /etc/os-release                           # image de base
docker exec quiz-initial ps -o user,pid,args                           # utilisateur
docker images quiz-docker:initial                                      # taille
docker history --no-trunc quiz-docker:initial                          # couches
docker save quiz-docker:initial -o quiz-initial.tar
docker run --rm -v trivy-cache:/root/.cache -v "$PWD":/scan:ro aquasec/trivy:0.69.1 \
  image --input /scan/quiz-initial.tar --scanners vuln                 # CVE
```

Tous les résultats bruts sont dans `audit/initial/` (fichiers 01 à 08, le scan complet en `.txt` et en `.json`).

### Tableau – état initial et risques identifiés

| Point vérifié | État initial | Risque |
|---|---|---|
| Fonctionnement | OK, HTTP 200 sur http://localhost:8083 | – |
| Image de base | `nginx:1.27-alpine` → Nginx 1.27.5 sur Alpine 3.21.3 (étape de build : `node:18-alpine`) | Nginx 1.27 et Node 18 ne sont plus maintenus : plus de correctifs de sécurité |
| Tag | `1.27-alpine` (version mineure seulement, pas de digest) | build pas reproductible, et on ne sait pas exactement ce qu'on embarque |
| Utilisateur | `Config.User` vide → **root** (uid 0). Le processus maître nginx tourne en root | si Nginx est compromis, l'attaquant est root dans le conteneur |
| Taille | **73,6 Mo** (21 Mo compressée) | plus de fichiers = plus de surface d'attaque |
| Couches | 21 entrées dans `docker history`, la grosse couche (38,7 Mo) c'est l'install de Nginx + modules | modules nginx inutiles pour un site statique (image-filter, xslt, geoip, njs) avec plein de librairies |
| Paquets | 68 paquets Alpine | idem |
| Outils présents | `sh`, `apk`, `curl`, `wget`, `nc`, `vi` | un attaquant peut télécharger/installer des outils (`apk`, `curl`) |
| Outils de dev (node, npm, git, gcc) | absents de l'image finale (multi-stage déjà là) | – |
| Vulnérabilités (Trivy) | **219** : 3 critiques, 67 élevées, 103 moyennes, 46 faibles – toutes ont un correctif | CVE critiques dans OpenSSL (`libssl3`, `libcrypto3`) et `brotli` |
| Scan de config (Trivy) | 2 alertes : pas d'instruction `USER` (HIGH), pas de `HEALTHCHECK` (LOW) | – |
| Capacités Linux | jeu par défaut de Docker (`CapEff: a80425fb`) | capacités pas nécessaires laissées au conteneur |
| Système de fichiers | en écriture | on peut modifier le site ou déposer des fichiers |
| Ressources | aucune limite CPU / mémoire / processus | un conteneur bogué ou attaqué peut saturer la machine |
| Redémarrage / santé | `restart: no`, pas de healthcheck | pas de reprise automatique, Docker ne sait pas si l'app répond |
| Socket Docker | non monté | – (bon point) |
| `.dockerignore` | présent mais minimal | – |

### Réponses aux questions

**L'image utilisée est-elle adaptée à une utilisation en production ?**
Pas vraiment. Le principe est bon (multi-stage, Alpine, juste Nginx à la fin), mais la version de Nginx n'est plus maintenue, l'image a 219 CVE connues dont 3 critiques, et tout tourne en root sans aucune limite. Pour du dev ça passe, en prod non.

**Quels composants sont réellement nécessaires pour exécuter l'application ?**
Comme c'est une app Vite, une fois compilée il reste juste des fichiers statiques (HTML, CSS, JS, images, ~57 ko). Il faut donc seulement : un serveur web (Nginx), ses librairies de base (musl, openssl, pcre2, zlib) et les fichiers du dossier `dist/`. Node, npm, Vite et les `node_modules` servent uniquement à la compilation. Les modules Nginx (images, XSLT, GeoIP, JavaScript njs), `curl` et le gestionnaire de paquets `apk` ne servent à rien pour servir un site statique.

**Quels risques de sécurité identifiez-vous ?**
- exécution en root ;
- versions plus maintenues → 219 CVE, dont des failles critiques dans OpenSSL ;
- outils exploitables par un attaquant (`apk`, `curl`, `wget`, `nc`) ;
- système de fichiers modifiable (défiguration du site, dépôt de fichiers) ;
- pas de limites de ressources (déni de service sur l'hôte) ;
- capacités Linux par défaut non retirées ;
- tags imprécis → on ne maîtrise pas ce qui est construit.

**Quelles améliorations recommanderiez-vous en priorité ?**
1. Mettre à jour l'image de base vers une version maintenue (c'est ça qui fait tomber la plupart des CVE).
2. Ne plus tourner en root.
3. Restreindre le conteneur à l'exécution : lecture seule, `cap_drop: ALL`, `no-new-privileges`, limites CPU/mémoire.
4. Retirer ce qui sert pas (modules Nginx, curl, apk).
5. Épingler les versions précisément (tag + digest) et scanner régulièrement.

---

## Mission 2 – Sécurisation

| Recommandation | Ce que j'ai fait |
|---|---|
| Images de base minimales | Alpine partout. Dans l'étape finale je supprime `curl`, les modules Nginx inutiles et le binaire `apk`, puis je repars de `scratch` et je copie le système nettoyé : l'image passe de 73,6 Mo à **21,5 Mo** et de 68 à **22 paquets**. |
| Pas de root | image de base `nginxinc/nginx-unprivileged` (Nginx officiel prévu pour tourner sans root, port 8080) + `USER 101:101` dans le Dockerfile + `user: "101:101"` dans le compose |
| `.dockerignore` | complété : `.git`, `node_modules`, `dist`, fichiers Docker, `.env` / clés, docs, dossier `audit`, fichiers `*.old` |
| Tags précis | `node:24.22.3-alpine3.24@sha256:…` et `nginxinc/nginx-unprivileged:1.31.7-alpine3.24@sha256:…` (version exacte + digest) |
| COPY plutôt que ADD | uniquement des `COPY` (ADD peut télécharger des URL et décompresser des archives tout seul) |
| Limiter ressources et privilèges | dans `docker-compose.yml` : `read_only: true` + `/tmp` en tmpfs `noexec`, `cap_drop: ALL`, `no-new-privileges:true`, 0,5 CPU, 128 Mo de RAM, 100 processus max, logs limités, `restart: unless-stopped` |
| Build multi-étapes | 3 étapes : `build` (Node compile l'app) → `web` (Nginx nettoyé + fichiers du site) → `scratch` (image finale en une seule couche) |
| Pas de socket Docker | aucun volume monté, et pas de `/var/run/docker.sock` (le monter = donner le contrôle de Docker donc de la machine). J'ai fait pareil pour le scanner Trivy (scan d'un `.tar`). |
| Vérifier régulièrement | `HEALTHCHECK` dans l'image ; scan Trivy des CVE (`audit/*/07-trivy.*`), scan de config du Dockerfile (`08-trivy-config.txt`) et `npm audit` des dépendances de build (`audit/secure/09-…`) |

Pour Nginx j'ai d'abord pris la 1.30.6 (branche « stable »), mais le scan a trouvé 4 CVE critiques corrigées en 1.30.7, et cette version n'était pas encore publiée en image. J'ai donc pris la **1.31.7 (branche mainline)**, qui est d'ailleurs celle que nginx.org conseille, et elle n'a pas ces CVE.

---

## Mission 3 – Comparaison avant / après

### Commandes

```bash
# construire et lancer (le compose fait le build et nomme l'image quiz-docker:secure)
docker compose up -d --build
docker compose ps                    # quiz-docker ... Up (healthy) 0.0.0.0:8082->8080/tcp
curl -s -o /dev/null -w "%{http_code}" http://localhost:8082     # 200

# ou sans compose :
docker build -t quiz-docker:secure .

# publication sur Docker Hub
docker login
docker tag quiz-docker:initial <identifiant-docker-hub>/quiz-docker:initial
docker tag quiz-docker:secure  <identifiant-docker-hub>/quiz-docker:secure
docker push <identifiant-docker-hub>/quiz-docker:initial
docker push <identifiant-docker-hub>/quiz-docker:secure
```

### Tableau comparatif

| Critère | `quiz-docker:initial` | `quiz-docker:secure` |
|---|---|---|
| Image de base (finale) | `nginx:1.27-alpine` (1.27.5, Alpine 3.21.3) | `nginx-unprivileged:1.31.7-alpine3.24` nettoyée puis aplatie sur `scratch` |
| Image de build | `node:18-alpine` (plus maintenu) | `node:24.22.3-alpine3.24` (LTS) |
| Tags | approximatifs | version exacte + digest |
| Taille | 73,6 Mo (21 Mo compressée) | **21,5 Mo** (5,9 Mo compressée) |
| Couches | 21 | 9 (dont une seule avec des fichiers) |
| Paquets Alpine | 68 | 22 |
| Outils de dev (node, npm, git, gcc) | absents | absents |
| Gestionnaire de paquets / curl | `apk`, `curl` présents | supprimés |
| Shell | oui (busybox) | oui (busybox, nécessaire au script de démarrage de Nginx) |
| `.dockerignore` | minimal | complet (secrets, docs, audit…) |
| Multi-stage build | oui (2 étapes) | oui (3 étapes) |
| Utilisateur | root (uid 0) | nginx (uid 101) |
| Port interne | 80 | 8080 |
| Healthcheck | non | oui (`healthy`) |
| Système de fichiers | écriture | lecture seule (+ `/tmp` en mémoire, noexec) |
| Capacités Linux | jeu par défaut | aucune (`cap_drop: ALL`, `CapEff: 0`) |
| Élévation de privilèges | possible | bloquée (`no-new-privileges`) |
| Limitation des ressources | aucune | 0,5 CPU, 128 Mo, 100 processus |
| Redémarrage auto | non | `unless-stopped` (testé : relancé après un crash) |
| Accès au socket Docker | non | non |
| CVE critiques | 3 | **0** |
| CVE élevées | 67 | **0** |
| CVE moyennes | 103 | **0** |
| CVE faibles | 46 | **0** |
| Total CVE | 219 | **0** |
| Alertes de config Trivy (Dockerfile) | 2 (pas de USER, pas de HEALTHCHECK) | 0 |

Tests faits sur le conteneur sécurisé (`audit/secure/06-contenu-et-privileges.txt`) : modifier le site → `Read-only file system`, écrire dans `/etc` → refusé, exécuter un script déposé dans `/tmp` → `Permission denied`, `apk add curl` → `apk: not found`.

### Questions d'analyse

**Quelles modifications ont apporté les améliorations les plus significatives ?**
Pour les CVE, c'est clairement le passage à une image de base à jour : rien que ça fait disparaître la grosse majorité des 219 failles, parce qu'elles avaient toutes déjà un correctif. Ensuite la suppression des modules Nginx et de curl enlève beaucoup de librairies (libxml2, libxslt, libgd, libpng, libcurl…), et la 1.31.7 règle les dernières failles de Nginx lui-même. Pour l'exécution, le plus important c'est le non-root et le système de fichiers en lecture seule : même si quelqu'un trouve une faille, il peut quasiment rien faire.

**La taille de l'image a-t-elle diminué ? Pourquoi ?**
Oui, de 73,6 Mo à 21,5 Mo (−70 %). Au début j'ai juste fait `apk del` dans un `RUN` et l'image était passée à 103 Mo ! Supprimer des fichiers dans une couche les cache seulement, ils restent dans les couches d'en dessous. C'est pour ça que j'ai ajouté une dernière étape `FROM scratch` + `COPY --from=web / /` : on copie uniquement ce qui reste après le nettoyage, dans une seule couche.

**Quelles recommandations concernent le Dockerfile et lesquelles concernent l'exécution du conteneur ?**
- Dockerfile (l'image) : image minimale, tags précis, multi-stage, `.dockerignore`, COPY au lieu de ADD, `USER` non-root, `HEALTHCHECK`, suppression des paquets inutiles.
- Exécution (`docker-compose.yml` ou options de `docker run`) : limites de ressources, `read_only`, `cap_drop`, `no-new-privileges`, politique de redémarrage, pas de montage du socket Docker.
- Le non-root est des deux côtés (`USER` dans l'image et `user:` dans le compose).
- Le scan régulier, c'est plutôt du processus (à faire en continu, pas une ligne de config).

**Votre image est-elle désormais totalement sécurisée ? Justifiez votre réponse.**
Non. « 0 CVE » ça veut dire 0 faille *connue* le 25/11/2026 dans les paquets que Trivy sait détecter. Il reste :
- de nouvelles CVE vont sortir, et comme les versions sont épinglées l'image ne se met pas à jour toute seule → il faut reconstruire et rescanner régulièrement ;
- il y a encore un shell (busybox, avec `wget`, `nc`, `vi`) parce que le script de démarrage de Nginx en a besoin ;
- les dépendances de build ont des failles (`npm audit` : 6, dont 5 élevées, dans Vite / Rollup / esbuild / PostCSS). Elles ne sont pas dans l'image finale, mais c'est un risque sur la chaîne de build. J'ai pas mis à jour Vite parce que le TP demande de pas toucher à l'application ;
- le site est en HTTP, pas de chiffrement TLS ;
- l'image n'est pas signée et n'a pas de SBOM ;
- en aplatissant sur `scratch`, on perd l'info « image de base » dans les métadonnées, donc un outil comme Docker Scout ne peut plus dire automatiquement « ta base Nginx a une mise à jour » ;
- quelqu'un qui a accès à Docker sur la machine peut toujours faire `docker exec -u 0` (mais sans capacités et en lecture seule, root peut pas faire grand chose).

**Quelles mesures complémentaires proposeriez-vous pour un déploiement en production ?**
- Automatiser le scan dans une pipeline CI (Trivy ou Docker Scout) qui bloque le déploiement si CVE critique/élevée ;
- Mettre à jour automatiquement les versions/digests (Dependabot ou Renovate) et reconstruire souvent ;
- Mettre à jour les dépendances npm (Vite 4 → version récente) ;
- Générer un SBOM et des attestations de provenance (`docker buildx build --sbom=true --provenance=mode=max`) et signer l'image (cosign / Docker Content Trust) ;
- Mettre un reverse proxy avec HTTPS devant (Traefik, Caddy…) et des en-têtes de sécurité (CSP, HSTS…) ;
- Profil seccomp / AppArmor, Docker en mode rootless ou user namespaces ;
- Surveiller les logs et le healthcheck (alertes) ;
- Envisager une image encore plus minimale sans shell, par exemple une Docker Hardened Image (mission 4).

---

## Mission 4 – Docker Hardened Images (DHI)

L'adresse donnée dans le sujet (`docs.docker.com/guides/lab-dhi-node/`) renvoie une erreur 404. L'atelier a été déplacé ici : https://docs.docker.com/learn/content/build-on-a-trusted-foundation/

Les images DHI sont sur le registre `dhi.io`. Elles sont gratuites (offre Community) mais il faut se connecter avec un compte Docker (`docker login dhi.io`).

### Ce qui est fait

L'application de l'atelier est dans `dhi/my-app/` (petite API Express qui répond `{"status":"ok"}` sur le port 3000) avec :
- `Dockerfile` : la version d'origine de l'atelier (`FROM node:22`, un seul étage, `npm install`) ;
- `Dockerfile.dhi` : la version migrée vers DHI (étape de build en `dhi.io/node:22-alpine3.23-dev`, étape finale en `dhi.io/node:22-alpine3.23`, `npm ci --omit=dev`).

Résultats sur l'image d'origine `my-app:1.0` (`dhi/resultats/01` et `02`) :
- 1,64 Go (412 Mo compressée), Debian 12, root ;
- outils présents : `bash`, `apt`, `npm`, `curl`, `wget`, `git`, `gcc`, `python3`, `make`… et `nodemon` (outil de dev) installé en prod ;
- **3 936 CVE** dans les paquets système (20 critiques, 482 élevées, 1 395 moyennes, 1 548 faibles, 491 inconnues) + 38 dans les dépendances npm (15 élevées).

### À faire avec mon compte Docker

```bash
cd dockerfile-exercice2/dhi
docker login dhi.io
bash dhi-commandes.sh
```

Le script construit `my-app:1.1` avec l'image DHI, vérifie qu'elle répond, qu'il n'y a pas de shell ni de npm, l'utilisateur, la taille, et lance le scan Trivy (résultats dans `dhi/resultats/03` à `05`).

### Comparaison DHI / mon image sécurisée

| | Mon image `quiz-docker:secure` | Docker Hardened Image (d'après la doc de l'atelier) |
|---|---|---|
| Non-root par défaut | oui, mais c'est moi qui l'ai configuré | oui, d'origine (uid 1000 pour Node) |
| Shell | encore présent (busybox) | absent de l'image runtime |
| Gestionnaire de paquets | supprimé à la main | absent de l'image runtime |
| CVE | 0 au moment du scan, mais à moi de maintenir | images reconstruites par Docker dès qu'un correctif sort |
| SBOM / provenance / signature | non | oui : SBOM signés, provenance SLSA niveau 3, déclarations VEX, signature de chaque image |
| Maintenance | manuelle (mise à jour des versions, rebuild) | faite par Docker, il faut juste rebuild |
| Débogage | `docker exec … sh` possible | plus difficile (pas de shell) : il faut `docker debug` ou la variante `-dev` |

Chiffres annoncés par l'atelier pour son exemple (pas mesurés par moi) : la migration fait passer l'image de 405 Mo à 38 Mo et les CVE de 2 critiques / 64 élevées à 0 critique / 4 élevées, les restantes étant dans les dépendances npm de l'appli.

**Conclusion** : pour la production, une DHI apporte des choses que j'ai pas réussi à faire moi-même : pas de shell du tout, des images signées avec SBOM, et surtout une maintenance faite par Docker. Mon image sécurisée arrive à un résultat proche en nombre de CVE, mais c'est du travail manuel qu'il faut refaire à chaque mise à jour. Pour le quiz il faudrait une DHI Nginx à la place de `nginx-unprivileged` (à vérifier dans le catalogue https://hub.docker.com/hardened-images/catalog).

---

## Synthèse

Au départ l'image marchait, mais elle tournait en root avec une version de Nginx plus maintenue et 219 vulnérabilités connues (dont 3 critiques). J'ai :
- mis à jour et épinglé les images (Node 24 LTS, Nginx 1.31.7, tag + digest) ;
- utilisé une image Nginx non-root et retiré ce qui servait à rien (modules Nginx, curl, apk) ;
- aplati l'image finale sur `scratch` pour qu'elle soit vraiment plus petite (73,6 → 21,5 Mo) ;
- complété le `.dockerignore` et ajouté un healthcheck ;
- lancé le conteneur avec Compose en lecture seule, sans capacités, sans élévation de privilèges, avec des limites de ressources et un redémarrage automatique.

Résultat : 0 CVE connue, 0 alerte de config, et l'app marche toujours (healthy, HTTP 200).

Risques qui restent : de nouvelles CVE vont forcément apparaître (il faut rescanner et reconstruire régulièrement), le shell busybox est encore là, les dépendances de build ont des failles, pas de HTTPS, pas de signature ni de SBOM. Une Docker Hardened Image réglerait une partie de ces points.

## Liens

- Dépôt Git : `<à compléter : lien du fork GitHub>`
- Images Docker Hub : `<à compléter : https://hub.docker.com/r/<identifiant>/quiz-docker>`
