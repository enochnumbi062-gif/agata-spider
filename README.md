# AgAtA-SpiDeR — Plateforme d'audit de sécurité autorisé

API FastAPI durcie + interface 3D (Three.js) servie par le même service. Un seul déploiement Render.

## Démarrage local
```bash
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt && cp .env.example .env
python -m pytest -q
uvicorn app.main:app --port 8000   # http://127.0.0.1:8000
```

## Déploiement Render (via GitHub)
1. Poussez ce dossier à la racine d'un dépôt GitHub.
2. Render → New → Blueprint → choisissez le dépôt (lit `render.yaml`).
3. Renseignez `GEMINI_API_KEY`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_ADMIN_CHAT_ID` (optionnels).
4. `AGATA_API_TOKEN` est généré par Render : copiez-le (Environment) et saisissez-le dans le module 10 de l'interface.
5. Vérifiez au premier test que la limitation de débit voit bien des IP distinctes ; sinon ajustez `AGATA_PROXY_HOPS`.

Plan gratuit : le disque est éphémère, les audits (SQLite) et le journal sont perdus à chaque redéploiement/redémarrage.

## Sécurité intégrée
- Contrôles actifs désactivés par défaut (fail-closed) ; liste blanche de cibles et de ports ; jeton obligatoire.
- Résolution DNS unique et adresse figée (anti DNS-rebinding), plages link-local/multicast/réservées bloquées (métadonnées cloud).
- Connexion TCP seulement : aucun exploit, brute force, furtivité ou persistance.
- Jeton Bearer comparé en temps constant, blocage après échecs répétés, limitation de débit par IP, corps de requête limité.
- CSP stricte, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy, documentation API désactivée.
- Journal JSONL chaîné SHA-256 (`GET /v1/integrity`) ; clé Gemini transmise par en-tête, jamais dans l'URL.
- Conteneur non-root, rootfs en lecture seule (compose), HEALTHCHECK.

## API
`GET /health` · `GET /v1/status` · `GET /v1/assets` · `POST /v1/audits/demo` (simulé, public)
Avec jeton : `GET /v1/audits` · `POST /v1/audits/connect-check` · `GET /v1/audits/{id}` · `GET /v1/audits/{id}/report.pdf` · `POST /v1/audits/{id}/telegram` · `GET /v1/integrity`

## Limites
Pas de SSO/RBAC multi-tenant ni de base externe. Modules 04, 06, 09, 11, 12, 14 : affichés « À venir ». Le drapeau `authorization_confirmed` n'est pas une autorisation légale : l'accord écrit du propriétaire reste indispensable.
