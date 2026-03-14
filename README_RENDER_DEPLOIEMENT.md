Forex Capture Analyzer Premium — Vrai système temps réel V28

# Forex Capture Analyzer PRO — Pack Render prêt à déployer

Ce pack répond exactement à ces attentes :

1. Mettre en ligne une app qui accompagne les traders.
2. Protéger l'accès par clé licence avec une page de connexion client.
3. Permettre, dans la même page de connexion, l'entrée d'une clé spéciale admin pour ouvrir la gestion des licences.

## Structure
- `public/index.html` : page de connexion client et admin
- `public/app.html` : application trader
- `public/admin.html` : dashboard admin pour gérer les licences
- `server.js` : API Render Node/Express
- `data/licenses.seed.json` : 1000 clés prédéfinies non utilisées
- `data/events.seed.json` : journal des événements initial

## Déploiement Render
### Option la plus simple
1. Crée un nouveau dépôt GitHub.
2. Envoie tout le contenu de ce dossier à la racine du dépôt.
3. Sur Render, clique sur **New +** puis **Web Service**.
4. Connecte le dépôt GitHub.
5. Vérifie ces réglages :
   - Runtime : `Node`
   - Build Command : `npm install`
   - Start Command : `npm start`
6. Ajoute les variables d'environnement :
   - `LICENSE_SECRET`
   - `ADMIN_TOKEN`
   - `ADMIN_MASTER_KEY`
7. Lance le déploiement.

## Clé admin
La même page `index.html` accepte :
- une clé licence client pour ouvrir `app.html`
- la valeur `ADMIN_MASTER_KEY` pour ouvrir `admin.html`

## Important
- Les 1000 licences sont préchargées au premier démarrage à partir de `data/licenses.seed.json`.
- Sans disque persistant Render, les modifications de licences peuvent être perdues lors d'un redéploiement majeur.
- Pour garder l'état des licences, attache un disque persistant Render puis définis `DATA_DIR` ou laisse `RENDER_DISK_PATH` être détecté automatiquement.

## Vérification
Après déploiement :
- `/` ouvre la page de connexion
- `/health` doit répondre avec `ok: true`
- la clé admin ouvre `admin.html`


Mise à jour V28 :
- Dashboard client avec suivi licence en temps réel par rafraîchissement automatique.
- Dashboard admin avec actualisation automatique des statistiques et de la liste des licences.
- Popup support épuré.


## Important — mémoire des licences sur Render

Pour que les licences expirées restent bloquées même après redémarrage, le service doit utiliser un disque persistant Render.

- Attacher un **Persistent Disk** au service.
- Vérifier que `RENDER_DISK_PATH` est disponible côté serveur.
- Le projet enregistre alors `licenses.json` et `events.json` dans ce disque.
- Au démarrage, le serveur **recalcule automatiquement** les statuts :
  - `expired` selon la date du serveur
  - `quota_reached` selon `analysis_count` par rapport à `analysis_limit`

Ainsi, une licence expirée ou un quota épuisé reste bloqué après redémarrage.
