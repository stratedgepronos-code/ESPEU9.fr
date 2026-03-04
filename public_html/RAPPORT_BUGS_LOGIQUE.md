# Rapport d’analyse — Bugs et erreurs de logique (projet u9/public_html)

**Périmètre :** api.php, index.html, equipe.html, gate.html  
**Exclu :** sécurité (traitée par un autre agent)

---

## 1. Erreurs JavaScript (références undefined, types, React/hooks)

### 1.1 Référence possible à un élément DOM null — gate.html
- **Fichier / contexte :** `gate.html`, fonction `showPanel(name)` (ligne ~557).
- **Description :** `document.getElementById('panel-' + name).classList.add('active')` est appelé sans vérifier que l’élément existe. Si `name` venait d’une source non fiable (ex. hash malformé ou futur lien), `getElementById` pourrait renvoyer `null` et `classList.add` lancer une exception.
- **Impact :** Exception JavaScript, formulaire bloqué.
- **Suggestion :** Vérifier l’élément avant utilisation, ex.  
  `const panel = document.getElementById('panel-' + name); if (panel) panel.classList.add('active');`

### 1.2 Propriété `min` potentiellement undefined — index.html / equipe.html
- **Fichier / contexte :** `getPlayerTotalStats()` (index.html ~328, equipe.html ~279).  
  `const parts = s.min.split(":");`
- **Description :** Les stats de match peuvent avoir `minutes` au lieu de `min`, ou `min`/`minutes` null/undefined (ex. données API ou feuille IA).
- **Impact :** `TypeError: Cannot read property 'split' of undefined` et blocage de l’affichage des totaux joueur.
- **Suggestion :** Utiliser une valeur par défaut, ex.  
  `const parts = (s.min != null ? s.min : s.minutes || '0:00').toString().split(':');`  
  et gérer les cas où `parts.length < 2` ou `parseInt(parts[0])`/`parseInt(parts[1])` donnent NaN.

### 1.3 Hooks React — index.html / equipe.html
- **Contexte :** Utilisation de `useState`, `useEffect`, `useRef` avec React en UMD.
- **Description :** Aucune violation évidente des règles des hooks (pas d’appels conditionnels ni en boucle). Les tableaux de dépendances de `useEffect` sont parfois vides `[]` alors que des closures capturent des valeurs (ex. `loadInbox`, `loadSent`, `loadUsers`) : comportement voulu pour un chargement initial, mais à documenter pour éviter des effets de bord si la logique évolue.
- **Impact :** Faible en l’état ; risque de bugs si on ajoute des dépendances sans revoir les effets.
- **Suggestion :** Garder des effets “mount-only” avec `[]` quand c’est voulu ; sinon ajouter les dépendances et gérer les re-exécutions (ex. annulation de fetch, refs).

---

## 2. Incohérences API (paramètres, réponses, cas d’erreur)

### 2.1 Action `get_team_data` absente de api.php — equipe.html
- **Fichier / contexte :** `equipe.html` : `loadTeamData()` appelle `API_URL + "action=get_team_data"` (ligne ~154). Aucun `case 'get_team_data'` dans `api.php`.
- **Description :** La page équipe repose sur une action qui n’existe pas dans ce backend.
- **Impact :** Réponse 400 “Action inconnue” ou comportement par défaut ; `j.success` reste faux, `TEAM_DATA_LOADED` n’est jamais mis à true, les callbacks ne s’exécutent pas → écran blanc ou chargement infini.
- **Suggestion :** Soit implémenter `get_team_data` dans api.php (avec paramètre `team`), soit faire pointer equipe.html vers un autre backend qui expose cette action, soit désactiver/rediriger equipe.html si non utilisée.

### 2.2 Paramètre `team` dans l’URL — equipe.html / api.php
- **Contexte :** equipe.html construit `API_URL = "/api.php?team=" + encodeURIComponent(TEAM_SLUG) + "&"`. api.php ne lit pas `$_GET['team']` pour router ou filtrer les données.
- **Description :** Le paramètre `team` est envoyé mais ignoré par l’API.
- **Impact :** Données potentiellement inadaptées si l’API doit un jour servir plusieurs équipes ; actuellement simple incohérence.
- **Suggestion :** Si le projet est multi-équipes, faire lire et valider `team` dans api.php et l’utiliser dans les requêtes ; sinon documenter ou retirer le paramètre côté front.

### 2.3 Réponses HTTP 4xx/5xx non vérifiées avant .json() — index.html
- **Fichier / contexte :** Nombreux `fetch(...).then(r => r.json()).then(...)` sans test de `r.ok` (ex. login ~2175, register ~2316, forgot_password ~2219, reset_password ~2265, get_inbox ~3208, get_sent, get_users, get_thread, send_message, get_convocation_responses, delete_match_sheet ~3480, etc.).
- **Description :** En cas de 401, 403, 404, 500, le corps peut être du JSON d’erreur ou du HTML. Appeler `r.json()` sans vérifier `r.ok` peut échouer (parse error) ou traiter un corps d’erreur comme succès.
- **Impact :** Messages utilisateur incorrects, états incohérents (ex. “Message envoyé” alors que le serveur a refusé), ou erreurs non catchées.
- **Suggestion :** Vérifier `r.ok` (ou `r.status`) avant de parser :  
  `if (!r.ok) throw new Error(r.statusText || 'Erreur ' + r.status); return r.json();`  
  et afficher un message d’erreur utilisateur cohérent dans le `.catch()`.

### 2.4 Même problème — gate.html
- **Contexte :** Tous les appels à l’API (check_session, login, register, forgot_password, reset_password, get_invite_info) font `.then(r => r.json())` sans vérifier le code HTTP.
- **Impact :** En cas de 429, 500 ou page d’erreur HTML, le JSON peut être invalide ou contenir une erreur non affichée correctement.
- **Suggestion :** Idem : vérifier `r.ok` (ou gérer 429/500) avant `r.json()` et afficher le message d’erreur renvoyé par l’API.

### 2.5 Réponse incohérente pour `verify_user_password` — api.php
- **Fichier / contexte :** api.php, case `verify_user_password` (lignes ~605–607). Utilisateur non trouvé : `echo json_encode(['match'=>false,'error'=>'User not found']);` sans clé `success`.
- **Description :** Les autres actions renvoient en général `success: true/false`. Ici, en cas d’utilisateur non trouvé, il n’y a pas de `success`, ce qui peut compliquer un traitement générique côté client.
- **Impact :** Faible ; le front (index.html ~2603) s’appuie sur `d.match` et gère bien l’absence de `display_name`/`username`.
- **Suggestion :** Pour homogénéité : renvoyer par ex. `['success'=>true, 'match'=>false, 'error'=>'User not found']` (ou `success=>false` selon la convention choisie).

### 2.6 get_invite_info et table `players` — api.php
- **Fichier / contexte :** api.php, case `get_invite_info` (lignes ~3001–3003) : requête `SELECT id, firstName, lastName FROM players`.
- **Description :** Le reste du projet utilise des joueurs en dur (ex. `get_player_info` avec tableau statique). La table `players` avec colonnes `firstName`/`lastName` peut être absente ou avoir un schéma différent.
- **Impact :** Exception SQL ou résultat vide ; le nom du joueur reste “Joueur #X” au lieu du vrai nom.
- **Suggestion :** Vérifier l’existence et le schéma de la table `players` ; sinon s’aligner sur la source de données réelle (table ou mapping statique cohérent avec le reste de l’app).

---

## 3. Logique métier (conditions, edge cases, race conditions)

### 3.1 Rate limit enregistré avant validation — api.php
- **Fichier / contexte :** `register` (ligne ~438) : `recordAttempt($clientIp, 'register');` est appelé avant les contrôles sur username, email, password, player_id.
- **Description :** Toute requête POST vers `register` consomme une tentative, même si les champs sont vides ou invalides.
- **Impact :** Un utilisateur qui se trompe plusieurs fois de formulaire peut atteindre la limite (5/heure) sans avoir envoyé une seule inscription valide.
- **Suggestion :** Déplacer `recordAttempt` après la validation des champs (ou ne compter que les tentatives “valides” selon la politique souhaitée). Idem à considérer pour `forgot_password` si besoin.

### 3.2 showPanel appelé avant que le DOM soit prêt — gate.html
- **Contexte :** Si le hash contient `#reset/TOKEN` ou `inscription`, `showPanel('reset')` ou `showPanel('register')` est appelé dans la même IIFE que `initForms()`, après le `check_session` asynchrone. Le DOM est déjà en place, donc risque faible.
- **Description :** En théorie, si `check_session` était très rapide et que le DOM n’était pas encore rendu, `getElementById` pourrait échouer. En pratique le flux actuel rend le risque faible.
- **Impact :** Très faible.
- **Suggestion :** Pour robustesse, s’assurer que `initForms()` (et donc `showPanel`) ne s’exécute qu’après que le DOM soit prêt (déjà le cas avec le script en bas de body).

### 3.3 Race condition sur plusieurs fetch messagerie — index.html
- **Contexte :** `loadInbox()`, `loadSent()`, `loadUsers()` sont appelées dans un `useEffect` sans annulation. Si l’utilisateur change vite de vue ou se déconnecte, les callbacks `setInbox`, `setSent`, `setUsers` peuvent s’exécuter après un changement d’état.
- **Description :** Classique “setState on unmounted component” ou mise à jour d’un état déjà obsolète.
- **Impact :** Warnings React possibles ou affichage temporairement incohérent.
- **Suggestion :** Utiliser un flag ou une ref “mounted” / “abort” et ignorer les résultats si la requête a été annulée ou le composant démonté (ou utiliser AbortController pour les fetch).

### 3.4 save_note : type de `ref_id` — api.php
- **Fichier / contexte :** api.php, case `save_note` (lignes 419–425). `$refId = $in['ref_id'] ?? '';` est passé tel quel en requête.
- **Description :** En JSON, `ref_id` peut être une chaîne (ex. `"47"` pour un match). La BDD peut accepter la chaîne si la colonne est VARCHAR ou si MySQL fait la conversion ; si la colonne est INT et qu’ailleurs on compare avec des entiers, des incohérences sont possibles.
- **Impact :** Selon le schéma et les index, risque de doublons (ex. ref_id 47 vs "47") ou d’erreurs.
- **Suggestion :** Caster explicitement : pour type `player` → `(int)$refId`, pour type `match` → selon le type de l’ID (int ou string) et utiliser le même type partout (ex. `(int)$refId` si les IDs sont numériques).

---

## 4. Données (format date, IDs, null/undefined)

### 4.1 Format de date incohérent (DD/MM/YYYY vs YYYY-MM-DD)
- **Contexte :** Front (index.html, equipe.html) : affichage et parfois parsing en “DD/MM/YYYY” (ex. UPCOMING, INITIAL_MATCHES). API / BDD : dates souvent en `Y-m-d` ou ISO.
- **Description :** Si l’API renvoie `date: "2026-03-08"` et que le front attend `"08/03/2026"`, les comparaisons ou affichages peuvent être faux sans conversion.
- **Impact :** Dates mal affichées ou mal triées ; anniversaires / absences / convocations si basés sur la date.
- **Suggestion :** Définir un format canonique côté API (ex. ISO) et une seule fonction de formatage côté client (ex. `formatDate(isoDate)` → DD/MM/YYYY pour l’affichage). Ne pas mélanger les formats dans les comparaisons.

### 4.2 IDs string vs number — index.html / API
- **Contexte :** Côté client, `player.id`, `matchId`, `user.id` viennent du JSON (souvent nombres). Côté API, beaucoup de `(int)$_GET['player_id']` ou `(int)$in['player_id']`.
- **Description :** Si le client envoie `player_id: "8"` (string), l’API caste en int ; si la BDD ou un autre endpoint renvoie un string, des comparaisons strictes (`id === 8`) peuvent échouer.
- **Impact :** Bugs discrets (ex. “ce n’est pas mon enfant”, mauvais filtre).
- **Suggestion :** Normaliser côté client : `parseInt(id, 10)` ou `Number(id)` pour les IDs avant envoi et pour les comparaisons. Côté API, continuer à caster en (int) pour les IDs numériques.

### 4.3 Données manquantes dans les réponses API
- **Contexte :** buildUserResponse et réponses “user” : champs optionnels `email`, `player_id`, `parent_type` avec `?? null`. Côté client, accès du type `user.player_id`, `user.email` sans toujours vérifier null.
- **Description :** Si un parent n’a pas de `player_id` (compte mal configuré) ou pas d’email, certaines vues (messagerie, convocations) peuvent supposer que ces champs existent.
- **Impact :** Erreurs “Cannot read property of null/undefined” ou affichage incorrect.
- **Suggestion :** Vérifier les champs optionnels avant usage (ex. `user && user.player_id != null`) et prévoir des messages ou masquages pour “pas de joueur lié” / “email non renseigné”.

---

## 5. UX / affichage (chargement, messages d’erreur)

### 5.1 Absence d’état de chargement sur le premier check_session — gate.html
- **Contexte :** gate.html : `fetch(API + '?action=check_session', ...).then(...).catch(...)` puis `initForms()`. Aucun indicateur pendant cette requête.
- **Description :** Sur connexion lente, l’utilisateur voit le formulaire de connexion puis une redirection sans savoir que la session est en cours de vérification.
- **Impact :** Impression de freeze ou de double affichage.
- **Suggestion :** Afficher un court message ou spinner “Vérification de la session…” jusqu’à la fin du check_session, puis soit redirection soit affichage du formulaire.

### 5.2 Erreurs réseau silencieuses — index.html
- **Contexte :** Plusieurs `.catch(() => {})` ou `.catch(() => setLoading(false))` sans message utilisateur (ex. get_parent_users, get_absences, loadInbox, loadSent, loadUsers, get_convocation_responses, delete_thread, get_thread).
- **Description :** En cas d’échec réseau ou serveur, l’utilisateur ne voit rien (liste vide, pas de toast).
- **Impact :** L’utilisateur peut croire qu’il n’y a pas de messages / absences / utilisateurs.
- **Suggestion :** Afficher un message générique (“Impossible de charger les données. Réessayer.”) ou un état d’erreur réessayable, au lieu d’un catch vide.

### 5.3 Formulaire reset sans token — gate.html
- **Contexte :** Panel “reset” : si l’utilisateur ouvre gate.html#reset (sans token) ou #reset/, `resetToken` reste vide. Au submit : “Lien de réinitialisation invalide.”
- **Description :** Comportement correct ; pas de lien “Retour à la connexion” visible dans le fragment lu (il existe dans le HTML panel-forgot mais pas dans panel-reset).
- **Impact :** Utilisateur bloqué sur le panel reset sans moyen évident de revenir à la connexion (selon la maquette).
- **Suggestion :** Vérifier que le panel reset contient bien un lien “Retour à la connexion” pour les cas où le token est absent ou expiré.

---

## 6. Compatibilité (APIs dépréciées, navigateurs)

### 6.1 Notification.requestPermission() — index.html / equipe.html
- **Contexte :** `await Notification.requestPermission()` utilisé pour les push. Sur certains navigateurs mobiles (iOS Safari ancien, etc.), l’API peut être absente ou différente.
- **Description :** Déjà protégé par `if (!reg) return { error: "..." }` et la vérification de `PushManager` / `serviceWorker`. Pas d’usage de méthodes dépréciées repéré.
- **Impact :** Faible.
- **Suggestion :** Documenter les navigateurs supportés ; éventuellement détecter l’absence de Notification et afficher un message explicite au lieu d’échouer silencieusement.

### 6.2 String.prototype.padStart — index.html
- **Contexte :** `getPlayerTotalStats` : `String(Math.round((totalMin / games) % 60)).padStart(2, "0")`. `padStart` est ES2017.
- **Description :** Support large sur les navigateurs récents ; peut manquer sur de très vieux navigateurs.
- **Impact :** Faible pour une app moderne.
- **Suggestion :** Si cible IE ou vieux Android, utiliser un polyfill ou une alternative (ex. `('0' + n).slice(-2)`).

---

## 7. Performance (requêtes en boucle, gros payloads)

### 7.1 Plusieurs requêtes parallèles sans limite — index.html
- **Contexte :** Messagerie : `loadInbox()`, `loadSent()`, `loadUsers()` en parallèle au montage. Dashboard coach : `Promise.all([get_attendance_stats, get_training_stats, get_absences])`. Pas de requêtes en boucle évidentes.
- **Description :** Plusieurs appels simultanés au chargement de la page ; acceptable si le serveur tient la charge.
- **Impact :** Pic de charge au premier chargement ; risque de rate limit si beaucoup d’onglets ou de connexions.
- **Suggestion :** Garder le parallélisme pour la réactivité ; éventuellement séquencer ou mettre en cache les données peu changeantes (ex. liste des utilisateurs).

### 7.2 Payload potentiellement lourd — get_player_info (api.php)
- **Contexte :** api.php, case `get_player_info` : renvoie un tableau associatif complet (coordonnées, parents, etc.) pour tous les joueurs en une fois.
- **Description :** Si le nombre de joueurs augmente, la réponse grossit. Pas de pagination ni de filtre.
- **Impact :** Temps de réponse et consommation mémoire côté client si beaucoup de joueurs.
- **Suggestion :** Pour une grosse équipe, envisager un endpoint par joueur (ex. `get_player_info&player_id=X`) ou une pagination.

### 7.3 get_inbox / get_sent : LIMIT 100
- **Contexte :** api.php : `LIMIT 100` sur les messages. Pas de pagination côté client.
- **Description :** Au-delà de 100 messages, les plus anciens ne sont jamais affichés.
- **Impact :** Historique tronqué sans que l’utilisateur le sache.
- **Suggestion :** Soit paginer (paramètres `before_id` / `page`), soit afficher “100 derniers messages” et un lien “Voir plus” déclenchant une requête suivante.

---

## Synthèse par fichier

| Fichier      | Nombre de points |
|-------------|-------------------|
| api.php     | 8                 |
| index.html  | 12                |
| equipe.html | 4                 |
| gate.html   | 5                 |

**Priorité recommandée :**  
1) Action `get_team_data` manquante + paramètre `team` (equipe.html inutilisable sans correctif).  
2) Vérification de `r.ok` sur les fetch (index.html, gate.html) pour éviter des états incohérents.  
3) Protection de `s.min` / `s.minutes` dans `getPlayerTotalStats`.  
4) Gestion des erreurs réseau (messages utilisateur au lieu de `.catch()` vides).  
5) Vérification de l’élément DOM dans `showPanel` (gate.html) et cohérence des types/ref_id et dates (API + client).
