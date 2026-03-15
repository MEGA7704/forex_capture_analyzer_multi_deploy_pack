
# Cloudflare Pages Front

Ce pack contient uniquement le front à déployer sur Cloudflare Pages.

## Fichiers
- index.html
- admin.html
- app.html
- pricing_catalog.json
- config.js

## Étape obligatoire
Ouvrir `config.js` et remplacer :

```js
window.FXA_CONFIG = {
  API_BASE: 'https://TON-BACKEND-RENDER.onrender.com'
};
```

par l'URL réelle de ton backend Render.

Exemple :

```js
window.FXA_CONFIG = {
  API_BASE: 'https://forex-capture-analyzer.onrender.com'
};
```

## Déploiement Cloudflare Pages
- Build command : aucune
- Output directory : `/`
- Deploy : upload direct de ce dossier ou connexion GitHub

## Important côté Render
Autoriser CORS pour ton domaine Cloudflare Pages.
