# Configurer le déploiement automatique Git → FTP (Hostinger)

À chaque **push sur la branche `main`**, GitHub envoie automatiquement le contenu de `public_html/` sur ton FTP Hostinger.

## 1. Récupérer tes identifiants FTP

Dans ton **panneau Hostinger** :
- Va dans **Fichiers** (ou **FTP**) / **Comptes FTP**
- Note : **serveur FTP** (ex. `ftp.espeu9.fr` ou `ftp.hostinger.com`), **utilisateur** et **mot de passe**

## 2. Ajouter les secrets dans GitHub

1. Ouvre : **https://github.com/stratedgepronos-code/ESPEU9.fr**
2. **Settings** → **Secrets and variables** → **Actions**
3. Clique sur **New repository secret** et crée **4 secrets** :

| Nom du secret    | Exemple / valeur |
|------------------|------------------|
| `FTP_SERVER`     | `ftp.espeu9.fr` ou l’hôte FTP indiqué par Hostinger |
| `FTP_USERNAME`   | Ton identifiant FTP |
| `FTP_PASSWORD`   | Ton mot de passe FTP |
| `FTP_REMOTE_PATH`| Chemin distant. Souvent `public_html` ou `.` (voir ci‑dessous) |

### Valeur de `FTP_REMOTE_PATH`

- Si en te connectant en FTP tu arrives **directement dans le dossier du site** (où se trouvent `index.html`, etc.) → mets **`.`**
- Si tu arrives dans un dossier parent et tu vois un sous-dossier **public_html** → mets **`public_html`**

(Sur Hostinger, c’est souvent **`public_html`** ou **`.`** selon le type de compte.)

## 3. Vérifier que ça marche

Après avoir enregistré les 4 secrets :

1. Fais un petit changement dans le projet (ou un push vide).
2. Va dans l’onglet **Actions** du dépôt GitHub.
3. Tu dois voir un workflow **“Deploy to FTP (Hostinger)”** qui se lance et passe au vert.

Une fois les secrets corrects, chaque push sur `main` enverra automatiquement les fichiers vers ton FTP.
