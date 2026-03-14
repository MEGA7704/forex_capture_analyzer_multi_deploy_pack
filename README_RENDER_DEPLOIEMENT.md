# Déploiement Render Free + persistance GitHub

Cette version ne dépend plus d'un Persistent Disk Render.

## Ce que fait cette version

- Les licences `mode = duration` sont bloquées selon la date du serveur.
- Les licences `mode = count` sont bloquées selon `analysis_count >= analysis_limit`.
- Les champs `status` et `analyses_remaining` sont recalculés automatiquement au démarrage et pendant l'utilisation.
- Les données licences et événements peuvent être sauvegardées dans GitHub pour survivre aux redémarrages Render Free.

## Variables Render à configurer

- `LICENSE_SECRET`
- `ADMIN_TOKEN`
- `ADMIN_MASTER_KEY`
- `GITHUB_TOKEN`
- `GITHUB_REPO`
- `GITHUB_BRANCH`
- `GITHUB_LICENSES_PATH`
- `GITHUB_EVENTS_PATH`

## Configuration GitHub

1. Crée un Personal Access Token GitHub avec accès **Contents: Read and Write**.
2. Dans Render > Environment, ajoute :
   - `GITHUB_TOKEN=...`
   - `GITHUB_REPO=nom-utilisateur/nom-du-repo`
   - `GITHUB_BRANCH=main`
   - `GITHUB_LICENSES_PATH=render_data/licenses.json`
   - `GITHUB_EVENTS_PATH=render_data/events.json`
3. Redéploie le service.

## Comportement

- Au démarrage, le serveur tente de relire les données depuis GitHub.
- Si les fichiers GitHub n'existent pas encore, ils sont créés automatiquement.
- À chaque modification critique, les fichiers sont réécrits dans GitHub.

## Important

Sans `GITHUB_TOKEN` et `GITHUB_REPO`, le projet fonctionne toujours, mais la persistance restera locale et peut être perdue sur Render Free.
