# Rapport d'audit — ESPE Basket U9

*Généré à partir de deux analyses (sécurité + bugs/logique).*

---

## Synthèse sécurité

### Critique
- **Données personnelles en dur** : `get_player_info` contient adresses, emails, téléphones en PHP. À déplacer en base ou config hors dépôt.
- **Secrets en clair** : `config.php` (DB, SMTP, clés API) ne doit jamais être commité ; idéalement hors `public_html` et en variables d’environnement.
- **Endpoint `setup`** : Création du compte coach sans authentification (seulement rate limit). Protéger par PIN/code à usage unique ou désactiver après première exécution.

### Élevé
- **CSRF** : Aucun token CSRF ; seule protection = cookie `SameSite=Strict`. Ajouter un token pour les actions sensibles (POST).
- **Session** : Pas de `session_regenerate_id(true)` après login → risque de fixation de session. À ajouter après une connexion réussie.
- **Contrôle d’accès** : `get_convocations`, `get_photos`, `get_match_extras`, `get_convocation_responses` accessibles sans vérification de session. Exiger au moins une session (ou restreindre par rôle/parent).
- **Upload (vault)** : Pas de vérification MIME réelle ; confiance en `original_name`. Utiliser `finfo_file()` et liste blanche de types.

### Moyen
- **XSS dans emails** : Variables (gymnase, heure RDV) insérées dans le corps HTML sans `htmlspecialchars`. Échapper avant envoi.
- **Logout** : Après `session_destroy()`, supprimer le cookie côté client pour invalider la session dans le navigateur.
- **Mot de passe reset** : Aligner sur l’inscription (8 car. min, lettre + chiffre) pour reset et coach_reset_password.
- **Erreurs API** : Ne pas renvoyer au client les détails (réponse Claude, erreur cURL). Logger côté serveur, message générique côté client.
- **HSTS** : Ajouter l’en-tête `Strict-Transport-Security` en HTTPS.

---

## Synthèse bugs / logique

### Bloquant
- **equipe.html** : Appelle `get_team_data` qui **n’existe pas** dans `api.php` (u9 single-team). La page peut rester blanche ou en chargement. Soit implémenter `get_team_data` dans l’API, soit adapter equipe.html pour utiliser les données existantes (ex. get_all / get_matches).

### Important
- **getPlayerTotalStats** : `s.min` peut être `undefined` ou un nombre si l’API renvoie un format différent → `s.min.split(":")` peut crasher. Vérifier le type / présence avant split.
- **Fetch sans vérifier `r.ok`** : Beaucoup de `fetch().then(r => r.json())` sans `if (!r.ok)` → en 4xx/5xx le JSON peut être un message d’erreur et provoquer des erreurs silencieuses.
- **Rate limit** : Sur `register` (et oublier mot de passe), le compteur est incrémenté avant validation des champs → formulaires invalides consomment des tentatives.

### Moyen
- **gate.html** : `document.getElementById('panel-' + name)` peut être null → vérifier avant d’appeler `classList.add`.
- **save_note** : `ref_id` non casté (string vs int) → cohérence BDD.
- **.catch(() => {})** vides : L’utilisateur ne voit pas les échecs de chargement (messagerie, absences, etc.). Afficher un message ou un état d’erreur.
- **Formats de date** : Mélange DD/MM/YYYY (front) et YYYY-MM-DD (API/BDD) ; s’assurer des conversions cohérentes.
- **get_invite_info** : S’appuie sur une table `players` qui peut être absente (données en JS dans index). Géré par try/catch ; à documenter.

### Mineur
- **padStart** (ES2017) : À noter si support de vieux navigateurs.
- **Pagination** : get_inbox / get_sent limités à 100 ; pas de pagination côté client ni message si tronqué.

---

## Priorités recommandées

1. **Sécurité** : `session_regenerate_id(true)` après login ; exiger une session pour `get_convocations`, `get_photos`, `get_match_extras`, `get_convocation_responses` ; échappement XSS dans les emails.
2. **Bugs** : Corriger `getPlayerTotalStats` (s.min) ; implémenter ou contourner `get_team_data` pour equipe.html ; ajouter des vérifications `r.ok` sur les fetch critiques.
3. **Renforcement** : Token CSRF ; protection de `setup` ; validation MIME sur les uploads ; HSTS.

Aucune modification automatique n’a été appliquée dans ce rapport.
