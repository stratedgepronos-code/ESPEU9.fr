# Déploiement automatique Git → Hostinger (SFTP / SSH)

À chaque **push sur `main`**, GitHub envoie le contenu de `public_html/` sur ton hébergement via **SFTP** (SSH port 65002). On n’utilise plus le FTP classique.

## 1. Où trouver les infos

Dans **Hostinger** → **Détails sur SSH** (ou **Avancé** → **Accès SSH**) :
- **IP** : 178.16.128.35 (ou l’IP indiquée)
- **Port** : 65002
- **Nom d’utilisateur** : u527192911 (ou le tien)
- **Mot de passe** : celui de la connexion SSH (bouton « Changer » si besoin)

Le **chemin distant** sur Hostinger est en général :  
`/home/u527192911/domains/espeu9.fr/public_html`  
(à confirmer dans le gestionnaire de fichiers Hostinger en regardant le chemin complet de `public_html`).

## 2. Secrets GitHub

Va dans le dépôt → **Settings** → **Secrets and variables** → **Actions**, puis crée ces secrets :

| Secret             | Valeur |
|--------------------|--------|
| `SSH_HOST`         | `178.16.128.35` (l’IP SSH Hostinger) |
| `SSH_USERNAME`     | `u527192911` (ton utilisateur SSH) |
| `SSH_PASSWORD`     | Le mot de passe SSH (celui de « Détails sur SSH ») |
| `SSH_REMOTE_PATH`  | `/home/u527192911/domains/espeu9.fr/public_html` (adapter si ton chemin est différent) |
| `SSH_PORT`         | (optionnel) `65002` — utilisé par défaut si absent |

Tu peux supprimer les anciens secrets FTP (`FTP_SERVER`, `FTP_USERNAME`, `FTP_PASSWORD`) s’ils existent.

## 3. Vérifier

1. Enregistre les secrets ci‑dessus.
2. Fais un push sur `main` (ou relance le workflow dans l’onglet **Actions**).
3. Le job « Deploy to FTP (Hostinger) » doit passer au vert et le site être à jour sur espeu9.fr.
