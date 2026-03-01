<?php
/**
 * ESPE BASKET U9 — API v5 : Sécurisée
 */
require_once 'config.php';

// ═══ FAILLE 9 — Session sécurisée ═══
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'domain' => '',
    'secure' => true,      // Cookie envoyé uniquement en HTTPS
    'httponly' => true,     // Inaccessible via JavaScript
    'samesite' => 'Strict' // Protection CSRF partielle
]);
session_start();

// ═══ FAILLE 4 — CORS restreint ═══
$allowedOrigins = ['https://espeu9.fr', 'https://www.espeu9.fr'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins)) {
    header('Access-Control-Allow-Origin: ' . $origin);
} else {
    header('Access-Control-Allow-Origin: https://espeu9.fr');
}
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Credentials: true');

// ═══ FAILLE 10 — Security headers ═══
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

$action = $_GET['action'] ?? '';

// ═══ Session utilisateur globale ═══
$uid = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : 0;
$role = $_SESSION['role'] ?? '';

// ═══ FAILLE 5 — Rate limiting login ═══
function checkRateLimit($ip, $action, $maxAttempts = 5, $windowSeconds = 900) {
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip VARCHAR(45) NOT NULL,
            action VARCHAR(50) NOT NULL,
            attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip_action (ip, action, attempted_at)
        )");
        // Clean old entries
        $db->prepare("DELETE FROM rate_limits WHERE attempted_at < DATE_SUB(NOW(), INTERVAL :w SECOND)")->execute([':w' => $windowSeconds]);
        // Count recent attempts
        $st = $db->prepare("SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = :ip AND action = :act AND attempted_at > DATE_SUB(NOW(), INTERVAL :w SECOND)");
        $st->execute([':ip' => $ip, ':act' => $action, ':w' => $windowSeconds]);
        $count = (int)$st->fetch()['cnt'];
        return $count < $maxAttempts;
    } catch (Exception $e) { return true; } // En cas d'erreur, on laisse passer
}
function recordAttempt($ip, $action) {
    try {
        $db = getDB();
        $db->prepare("INSERT INTO rate_limits (ip, action) VALUES (:ip, :act)")->execute([':ip' => $ip, ':act' => $action]);
    } catch (Exception $e) {}
}
function clearAttempts($ip, $action) {
    try {
        $db = getDB();
        $db->prepare("DELETE FROM rate_limits WHERE ip = :ip AND action = :act")->execute([':ip' => $ip, ':act' => $action]);
    } catch (Exception $e) {}
}

function buildUserResponse($user) {
    return [
        'id' => (int)$user['id'],
        'username' => $user['username'],
        'role' => $user['role'],
        'display_name' => $user['display_name'],
        'email' => $user['email'] ?? null,
        'player_id' => $user['player_id'] ? (int)$user['player_id'] : null,
        'parent_type' => $user['parent_type'] ?? null
    ];
}

/*
 * ═══ CONFIGURATION EMAIL ═══
 */
if (!defined('SMTP_ENABLED')) define('SMTP_ENABLED', true);
if (!defined('SMTP_HOST'))    define('SMTP_HOST', 'smtp.hostinger.com');
if (!defined('SMTP_PORT'))    define('SMTP_PORT', 587);
if (!defined('SMTP_USER'))    define('SMTP_USER', 'noreply@espeu9.fr');
if (!defined('SMTP_PASS'))    define('SMTP_PASS', 'qx2Z&fSKO^sqjhYD');

function sendEmailNotif($toEmail, $subject, $body) {
    if (!$toEmail) return false;
    $fromName = 'ESPE Basket U9';
    $fromEmail = SMTP_USER ?: 'noreply@espeu9.fr';
    $html = "<div style='font-family:Arial,sans-serif;max-width:600px;margin:0 auto'>"
        ."<div style='background:#1a6b2e;color:#fff;padding:16px 24px;border-radius:8px 8px 0 0'>"
        ."<h2 style='margin:0'>ESPE Basket U9</h2></div>"
        ."<div style='padding:20px 24px;background:#fff;border:1px solid #e0e0e0;border-top:none;border-radius:0 0 8px 8px'>"
        ."<h3 style='color:#1a6b2e'>".htmlspecialchars($subject, ENT_QUOTES, 'UTF-8')."</h3>"
        ."<div style='line-height:1.6'>$body</div>"
        ."<hr style='border:none;border-top:1px solid #eee;margin:20px 0'>"
        ."<p style='font-size:12px;color:#999'>Connecte-toi sur <a href='https://espeu9.fr/#messagerie'>espeu9.fr</a> pour répondre.</p>"
        ."</div></div>";
    $fullSubject = "ESPE U9 - $subject";

    // Try SMTP if enabled
    if (SMTP_ENABLED && SMTP_USER && SMTP_PASS) {
        return sendSmtp($fromEmail, $fromName, $toEmail, $fullSubject, $html);
    }

    // Fallback: PHP mail() with improved headers
    $headers  = "From: $fromName <$fromEmail>\r\n";
    $headers .= "Reply-To: $fromEmail\r\n";
    $headers .= "Return-Path: $fromEmail\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "X-Mailer: ESPE-U9\r\n";
    return @mail($toEmail, $fullSubject, $html, $headers, "-f$fromEmail");
}

function sendSmtp($from, $fromName, $to, $subject, $htmlBody) {
    $host = SMTP_HOST; $port = SMTP_PORT;
    $user = SMTP_USER; $pass = SMTP_PASS;
    try {
        $sock = @fsockopen("tls://$host", $port, $errno, $errstr, 10);
        if (!$sock) { $sock = @fsockopen($host, $port, $errno, $errstr, 10); }
        if (!$sock) return false;
        stream_set_timeout($sock, 10);
        $resp = fgets($sock, 512);
        fputs($sock, "EHLO espeu9.fr\r\n"); $resp = '';
        while ($line = fgets($sock, 512)) { $resp .= $line; if (substr($line, 3, 1) == ' ') break; }
        // STARTTLS if not already TLS
        if (strpos($resp, 'STARTTLS') !== false && $port == 587) {
            fputs($sock, "STARTTLS\r\n"); fgets($sock, 512);
            stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            fputs($sock, "EHLO espeu9.fr\r\n");
            while ($line = fgets($sock, 512)) { if (substr($line, 3, 1) == ' ') break; }
        }
        // AUTH LOGIN
        fputs($sock, "AUTH LOGIN\r\n"); fgets($sock, 512);
        fputs($sock, base64_encode($user) . "\r\n"); fgets($sock, 512);
        fputs($sock, base64_encode($pass) . "\r\n");
        $authResp = fgets($sock, 512);
        if (substr($authResp, 0, 3) != '235') { fclose($sock); return false; }
        // MAIL FROM / RCPT TO
        fputs($sock, "MAIL FROM:<$from>\r\n"); fgets($sock, 512);
        fputs($sock, "RCPT TO:<$to>\r\n"); fgets($sock, 512);
        fputs($sock, "DATA\r\n"); fgets($sock, 512);
        // Headers + body
        $msg  = "From: $fromName <$from>\r\n";
        $msg .= "To: $to\r\n";
        $msg .= "Subject: $subject\r\n";
        $msg .= "MIME-Version: 1.0\r\n";
        $msg .= "Content-Type: text/html; charset=UTF-8\r\n";
        $msg .= "\r\n" . $htmlBody . "\r\n.\r\n";
        fputs($sock, $msg); fgets($sock, 512);
        fputs($sock, "QUIT\r\n");
        fclose($sock);
        return true;
    } catch (Exception $e) { return false; }
}

// ═══ Envoyer un email à TOUS les parents inscrits ═══
function notifyAllParents($subject, $htmlBody) {
    try {
        $db = getDB();
        $st = $db->query("SELECT email FROM users WHERE role='parent' AND email IS NOT NULL AND email != ''");
        while ($p = $st->fetch()) {
            if ($p['email']) sendEmailNotif($p['email'], $subject, $htmlBody);
        }
    } catch (Exception $e) { /* Pas de blocage si erreur email */ }
}

switch ($action) {

// ═══ FAILLE 1 — Données personnelles côté serveur uniquement ═══
case 'get_player_info':
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') {
        http_response_code(403); echo json_encode(['error' => 'Accès réservé au coach']); break;
    }
    // Données personnelles des joueurs — JAMAIS exposées côté client
    $playerInfo = [
        1 => [
            'lieuNaissance' => '51000 - Châlons en Champagne',
            'adresse' => '21 rue des Jardins', 'ville' => '51520 - SARRY',
            'email' => 'mel.mucolli@hotmail.fr', 'tel' => '06 70 68 12 06',
            'parent1' => ['nom' => 'HAUTION', 'prenom' => 'Mélinda', 'email' => 'mel.mucolli@hotmail.fr', 'tel' => '06 70 68 12 06'],
            'parent2' => ['nom' => 'HAUTION', 'prenom' => 'Pascal', 'email' => 'pascal.haution@hotmail.fr', 'tel' => '06 18 98 05 65'],
        ],
        2 => [
            'lieuNaissance' => '51000 - Châlons en Champagne',
            'adresse' => '76 Rue Léon Bourgeois', 'ville' => '51000 - CHÂLONS EN CHAMPAGNE',
            'email' => 'damiencollard@ymail.com', 'tel' => '06 85 22 30 30',
            'parent1' => ['nom' => 'COLLARD', 'prenom' => 'Damien', 'email' => 'damiencollard@ymail.com', 'tel' => '06 85 22 30 30'],
            'parent2' => ['nom' => 'COLLARD', 'prenom' => 'Eléonore', 'email' => 'edemarcke@hotmail.com', 'tel' => '06 74 86 70 27'],
        ],
        3 => [
            'lieuNaissance' => '51100 - Reims',
            'adresse' => '09 Rue du Consistoire', 'ville' => '51000 - CHÂLONS EN CHAMPAGNE',
            'email' => 'benoit.hamm@gmail.com', 'tel' => '06 89 56 75 85',
            'parent1' => ['nom' => 'HAMM', 'prenom' => 'Audrey', 'email' => 'audrey.brachet@gmail.com', 'tel' => '06 89 56 75 85'],
            'parent2' => ['nom' => 'HAMM', 'prenom' => 'Benoit', 'email' => 'benoit.hamm@gmail.com', 'tel' => '06 89 01 11 09'],
        ],
        4 => [
            'lieuNaissance' => '51100 - Reims',
            'adresse' => '24 rue du Grand Mau', 'ville' => '51470 - SAINT-MEMMIE',
            'email' => 'n.ameel@hotmail.fr', 'tel' => '06 71 53 87 15',
            'parent1' => ['nom' => 'GOUBAUX', 'prenom' => 'Amelie', 'email' => 'N.ameel@hotmail.fr', 'tel' => '06 71 53 87 15'],
            'parent2' => ['nom' => 'SLAH', 'prenom' => 'Samir', 'email' => '', 'tel' => '06 63 96 74 99'],
        ],
        5 => [
            'lieuNaissance' => '51100 - Reims',
            'adresse' => '162 D rue du camp d\'Attila', 'ville' => '51000 - CHÂLONS EN CHAMPAGNE',
            'email' => 'monica.alves@outlook.fr', 'tel' => '07 61 03 77 78',
            'parent1' => ['nom' => 'FRANCART', 'prenom' => 'Monica', 'email' => 'monica.alves@outlook.fr', 'tel' => '07 61 03 77 78'],
            'parent2' => ['nom' => 'FRANCART', 'prenom' => 'Guillaume', 'email' => 'guillaume.francart@live.fr', 'tel' => '06 98 36 18 20'],
        ],
        6 => [
            'lieuNaissance' => '51100 - Reims',
            'adresse' => '14 rue Cosme Clause', 'ville' => '51000 - CHÂLONS EN CHAMPAGNE',
            'email' => 'claire.starossenko@gmail.com', 'tel' => '07 83 33 82 95',
            'parent1' => ['nom' => 'STAROSSENKO', 'prenom' => 'Claire', 'email' => 'Claire.starossenko@gmail.com', 'tel' => '07 83 33 82 95'],
            'parent2' => ['nom' => 'DELE', 'prenom' => 'Jonathan', 'email' => 'Jonathan.dele@gmail.com', 'tel' => '06 66 89 07 96'],
        ],
        7 => [
            'lieuNaissance' => '51100 - Reims',
            'adresse' => '7, rue du pont Alips', 'ville' => '51470 - SAINT-MEMMIE',
            'email' => 'julie.mestrude@hotmail.fr', 'tel' => '06 62 49 31 82',
            'parent1' => ['nom' => 'FALZON MESTRUDE', 'prenom' => 'Julie', 'email' => 'julie.mestrude@hotmail.fr', 'tel' => '06 62 49 31 82'],
            'parent2' => ['nom' => 'FALZON', 'prenom' => 'Oswald', 'email' => 'oswald.falzon@gmail.com', 'tel' => '06 88 99 76 62'],
        ],
        8 => [
            'lieuNaissance' => '51200 - Épernay',
            'adresse' => '15 rue du lycée', 'ville' => '51000 - CHÂLONS EN CHAMPAGNE',
            'email' => 'elodie.lebegue51@outlook.fr', 'tel' => '06 98 66 27 20',
            'parent1' => ['nom' => 'LEBEGUE', 'prenom' => 'Elodie', 'email' => 'elodie.lebegue51@outlook.fr', 'tel' => '06 98 66 27 20'],
            'parent2' => ['nom' => 'FISCHESSER', 'prenom' => 'Thierry', 'email' => 'contact@alegra51.com', 'tel' => ''],
        ],
    ];
    echo json_encode(['success' => true, 'data' => $playerInfo]);
    break;

case 'get_all':
    try {
        $db = getDB();
        $stmt = $db->prepare("SELECT ref_id, content FROM coach_notes WHERE type = 'player'"); $stmt->execute();
        $pn = []; while ($r = $stmt->fetch()) { $pn[$r['ref_id']] = $r['content'] ?? ''; }
        $stmt = $db->prepare("SELECT ref_id, content FROM coach_notes WHERE type = 'match'"); $stmt->execute();
        $mn = []; while ($r = $stmt->fetch()) { $mn[$r['ref_id']] = $r['content'] ?? ''; }
        echo json_encode(['success'=>true,'coachNotes'=>$pn,'matchNotes'=>$mn]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur']); }
    break;

case 'login':
    if ($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'login', 5, 900)) {
        http_response_code(429);
        echo json_encode(['error' => 'Trop de tentatives. Réessaye dans 15 minutes.']);
        break;
    }
    $in = json_decode(file_get_contents('php://input'),true);
    $u=trim($in['username']??''); $p=$in['password']??'';
    if(!$u||!$p){http_response_code(400);echo json_encode(['error'=>'Remplis tous les champs']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT * FROM users WHERE username=:u OR email=:e LIMIT 1");
        $st->execute([':u'=>$u,':e'=>$u]);
        $user=$st->fetch();
        if($user && password_verify($p,$user['password_hash'])){
            clearAttempts($clientIp, 'login');
            $_SESSION['user_id']=$user['id']; $_SESSION['username']=$user['username']; $_SESSION['role']=$user['role'];
            $_SESSION['display_name']=$user['display_name']; $_SESSION['email']=$user['email']??null;
            $_SESSION['player_id']=$user['player_id']; $_SESSION['parent_type']=$user['parent_type'];
            echo json_encode(['success'=>true,'user'=>buildUserResponse($user)]);
        } else { recordAttempt($clientIp, 'login'); http_response_code(401); echo json_encode(['error'=>'Identifiant ou mot de passe incorrect']); }
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'logout': session_destroy(); echo json_encode(['success'=>true]); break;

case 'check_session':
    if(isset($_SESSION['user_id'])){
        echo json_encode(['logged_in'=>true,'user'=>[
            'id'=>(int)$_SESSION['user_id'],'username'=>$_SESSION['username'],'role'=>$_SESSION['role'],
            'display_name'=>$_SESSION['display_name'],'email'=>$_SESSION['email']??null,
            'player_id'=>$_SESSION['player_id']?(int)$_SESSION['player_id']:null,'parent_type'=>$_SESSION['parent_type']??null
        ]]);
    } else { echo json_encode(['logged_in'=>false]); }
    break;

case 'save_note':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $type=$in['type']??''; $refId=$in['ref_id']??''; $content=trim($in['content']??'');
    if(!in_array($type,['player','match'])||empty($refId)){http_response_code(400);echo json_encode(['error'=>'Invalide']);break;}
    if(strlen($content)>5000) $content=substr($content,0,5000);
    try {
        $db=getDB();
        $st=$db->prepare("INSERT INTO coach_notes (type,ref_id,content) VALUES(:t,:r,:c) ON DUPLICATE KEY UPDATE content=:c2,updated_at=CURRENT_TIMESTAMP");
        $st->execute([':t'=>$type,':r'=>$refId,':c'=>$content,':c2'=>$content]);
        echo json_encode(['success'=>true]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'register':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    // Rate limit: max 5 inscriptions par IP par heure
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'register', 5, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de tentatives. Réessaye plus tard.']); break;
    }
    recordAttempt($clientIp, 'register');
    $in=json_decode(file_get_contents('php://input'),true);
    $username=trim($in['username']??''); $password=$in['password']??''; $email=trim($in['email']??'');
    $playerId=$in['player_id']??null; $parentType=$in['parent_type']??'papa'; $playerName=trim($in['player_name']??'');
    if(!$username||!$password){http_response_code(400);echo json_encode(['error'=>'Identifiant et mot de passe requis']);break;}
    if(strlen($username)<3||strlen($username)>50){http_response_code(400);echo json_encode(['error'=>'Identifiant : 3 à 50 caractères']);break;}
    if(!preg_match('/^[a-zA-Z0-9._-]+$/',$username)){http_response_code(400);echo json_encode(['error'=>'Identifiant : lettres, chiffres, points et tirets uniquement']);break;}
    if(strlen($password)<6){http_response_code(400);echo json_encode(['error'=>'Mot de passe trop court (6 min)']);break;}
    if(!$playerId){http_response_code(400);echo json_encode(['error'=>'Sélectionne un joueur']);break;}
    if(!in_array($parentType,['papa','maman'])) $parentType='papa';
    $displayName=ucfirst($parentType).' de '.$playerName;
    try {
        $db=getDB(); $hash=password_hash($password,PASSWORD_DEFAULT);
        $st=$db->prepare("INSERT INTO users (username,password_hash,display_name,email,role,player_id,parent_type) VALUES(:u,:p,:d,:e,'parent',:pid,:pt)");
        $st->execute([':u'=>$username,':p'=>$hash,':d'=>$displayName,':e'=>$email?:null,':pid'=>$playerId,':pt'=>$parentType]);
        $newId=$db->lastInsertId();
        $_SESSION['user_id']=$newId; $_SESSION['username']=$username; $_SESSION['role']='parent';
        $_SESSION['display_name']=$displayName; $_SESSION['email']=$email?:null;
        $_SESSION['player_id']=$playerId; $_SESSION['parent_type']=$parentType;
        echo json_encode(['success'=>true,'user'=>['id'=>(int)$newId,'username'=>$username,'role'=>'parent',
            'display_name'=>$displayName,'email'=>$email?:null,'player_id'=>(int)$playerId,'parent_type'=>$parentType]]);
    } catch(PDOException $e){
        if($e->getCode()==23000){http_response_code(409);echo json_encode(['error'=>"L'identifiant '$username' existe déjà"]);}
        else{http_response_code(500);echo json_encode(['error'=>'Erreur création compte']);}
    }
    break;

case 'forgot_password':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'forgot', 3, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de demandes. Réessaye dans 1 heure.']); break;
    }
    recordAttempt($clientIp, 'forgot');
    $in=json_decode(file_get_contents('php://input'),true);
    $identifier=trim($in['identifier']??'');
    if(!$identifier){http_response_code(400);echo json_encode(['error'=>'Entre ton identifiant ou ton email']);break;}
    try {
        $db=getDB();
        // Create password_resets table if not exists
        $db->exec("CREATE TABLE IF NOT EXISTS password_resets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token VARCHAR(64) NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            used TINYINT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        // Find user by username or email
        $st=$db->prepare("SELECT id,email,display_name FROM users WHERE username=:u OR email=:e LIMIT 1");
        $st->execute([':u'=>$identifier,':e'=>$identifier]);
        $user=$st->fetch();
        // Always show success (security: don't reveal if account exists)
        if($user && $user['email']){
            // Generate token
            $token=bin2hex(random_bytes(32));
            $expires=date('Y-m-d H:i:s',strtotime('+1 hour'));
            // Delete old tokens for this user
            $st2=$db->prepare("DELETE FROM password_resets WHERE user_id=:uid");
            $st2->execute([':uid'=>$user['id']]);
            // Insert new token
            $st3=$db->prepare("INSERT INTO password_resets (user_id,token,expires_at) VALUES(:uid,:tok,:exp)");
            $st3->execute([':uid'=>$user['id'],':tok'=>$token,':exp'=>$expires]);
            // Send email
            $resetUrl="https://espeu9.fr/#reset/".$token;
            $body="<p>Bonjour <strong>".$user['display_name']."</strong>,</p>";
            $body.="<p>Tu as demandé la réinitialisation de ton mot de passe.</p>";
            $body.="<p style='text-align:center;margin:24px 0'><a href='".$resetUrl."' style='display:inline-block;padding:14px 28px;background:#1a6b2e;color:white;text-decoration:none;border-radius:10px;font-weight:bold;font-size:16px'>Réinitialiser mon mot de passe</a></p>";
            $body.="<p style='font-size:13px;color:#777'>Ce lien expire dans 1 heure.<br>Si tu n'as pas fait cette demande, ignore cet email.</p>";
            sendEmailNotif($user['email'],'Réinitialisation du mot de passe',$body);
        }
        echo json_encode(['success'=>true,'message'=>'Si un compte existe avec cet identifiant, un email a été envoyé.']);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'reset_password':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $token=trim($in['token']??'');
    $newPassword=$in['password']??'';
    if(!$token||!$newPassword){http_response_code(400);echo json_encode(['error'=>'Token et mot de passe requis']);break;}
    if(strlen($newPassword)<6){http_response_code(400);echo json_encode(['error'=>'Mot de passe trop court (6 caractères minimum)']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT * FROM password_resets WHERE token=:t AND used=0 AND expires_at > NOW() LIMIT 1");
        $st->execute([':t'=>$token]);
        $reset=$st->fetch();
        if(!$reset){http_response_code(400);echo json_encode(['error'=>'Lien invalide ou expiré. Refais une demande.']);break;}
        // Update password
        $hash=password_hash($newPassword,PASSWORD_DEFAULT);
        $st2=$db->prepare("UPDATE users SET password_hash=:h WHERE id=:uid");
        $st2->execute([':h'=>$hash,':uid'=>$reset['user_id']]);
        // Mark token as used
        $st3=$db->prepare("UPDATE password_resets SET used=1 WHERE id=:id");
        $st3->execute([':id'=>$reset['id']]);
        echo json_encode(['success'=>true,'message'=>'Mot de passe modifié ! Tu peux te connecter.']);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'coach_reset_password':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Réservé au coach']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $userId=(int)($in['user_id']??0);
    $newPassword=$in['password']??'';
    if(!$userId||!$newPassword){http_response_code(400);echo json_encode(['error'=>'Champs requis']);break;}
    if(strlen($newPassword)<6){http_response_code(400);echo json_encode(['error'=>'6 caractères minimum']);break;}
    try {
        $db=getDB();
        $hash=password_hash($newPassword,PASSWORD_DEFAULT);
        $st=$db->prepare("UPDATE users SET password_hash=:h WHERE id=:uid AND role='parent'");
        $st->execute([':h'=>$hash,':uid'=>$userId]);
        if($st->rowCount()>0){
            echo json_encode(['success'=>true,'message'=>'Mot de passe réinitialisé !']);
        } else {
            http_response_code(404);echo json_encode(['error'=>'Utilisateur non trouvé']);
        }
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'get_parent_users':
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Réservé au coach']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT id,username,display_name,email FROM users WHERE role='parent' ORDER BY display_name");
        $st->execute();
        $users=[];while($r=$st->fetch(PDO::FETCH_ASSOC)){$users[]=$r;}
        echo json_encode(['success'=>true,'users'=>$users]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'test_email':
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $toEmail=trim($in['email']??'');
    if(!$toEmail){http_response_code(400);echo json_encode(['error'=>'Email requis']);break;}
    $result = sendEmailNotif($toEmail, 'Test email ESPE U9', '<p>Si tu vois ce message, les emails fonctionnent ! ✅</p><p>Envoyé le '.date('d/m/Y H:i').'</p>');
    echo json_encode(['success'=>true,'mail_result'=>$result,'smtp_enabled'=>SMTP_ENABLED,'note'=>$result?'Email envoyé (vérifie ta boîte + spams)':'Echec envoi - vérifie SMTP dans config.php']);
    break;

case 'verify_user_password':
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $userId=(int)($in['user_id']??0);
    $testPwd=$in['password']??'';
    if(!$userId||!$testPwd){http_response_code(400);echo json_encode(['error'=>'Champs requis']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT username,password_hash,display_name FROM users WHERE id=:uid LIMIT 1");
        $st->execute([':uid'=>$userId]);
        $u=$st->fetch();
        if(!$u){echo json_encode(['match'=>false,'error'=>'User not found']);break;}
        $match=password_verify($testPwd,$u['password_hash']);
        echo json_encode(['success'=>true,'match'=>$match,'username'=>$u['username'],'display_name'=>$u['display_name']]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

// ═══ NOTIFICATIONS PUSH ═══

case 'vapid_public_key':
    require_once 'web_push.php';
    echo json_encode(['success'=>true,'key'=>VAPID_PUBLIC_KEY]);
    break;

case 'push_subscribe':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $endpoint=$in['endpoint']??'';
    $p256dh=$in['keys']['p256dh']??'';
    $auth=$in['keys']['auth']??'';
    if(!$endpoint||!$p256dh||!$auth){http_response_code(400);echo json_encode(['error'=>'Données manquantes']);break;}
    try {
        $db=getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            endpoint TEXT NOT NULL,
            p256dh VARCHAR(255) NOT NULL,
            auth VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_endpoint (endpoint(500))
        )");
        $st=$db->prepare("INSERT INTO push_subscriptions (user_id,endpoint,p256dh,auth) VALUES(:uid,:ep,:pk,:au) ON DUPLICATE KEY UPDATE user_id=:uid2,p256dh=:pk2,auth=:au2");
        $st->execute([':uid'=>$_SESSION['user_id'],':ep'=>$endpoint,':pk'=>$p256dh,':au'=>$auth,':uid2'=>$_SESSION['user_id'],':pk2'=>$p256dh,':au2'=>$auth]);
        echo json_encode(['success'=>true]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'push_unsubscribe':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $endpoint=$in['endpoint']??'';
    try {
        $db=getDB();
        $st=$db->prepare("DELETE FROM push_subscriptions WHERE endpoint=:ep");
        $st->execute([':ep'=>$endpoint]);
        echo json_encode(['success'=>true]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'push_status':
    if(!isset($_SESSION['user_id'])){echo json_encode(['subscribed'=>false]);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT COUNT(*) as cnt FROM push_subscriptions WHERE user_id=:uid");
        $st->execute([':uid'=>$_SESSION['user_id']]);
        $r=$st->fetch();
        $total=$db->query("SELECT COUNT(*) as cnt FROM push_subscriptions")->fetch();
        echo json_encode(['subscribed'=>(int)$r['cnt']>0,'total_subscribers'=>(int)$total['cnt']]);
    } catch(Exception $e){echo json_encode(['subscribed'=>false,'total_subscribers'=>0]);}
    break;

case 'send_push':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Réservé au coach']);break;}
    require_once 'web_push.php';
    $in=json_decode(file_get_contents('php://input'),true);
    $title=trim($in['title']??'');
    $body=trim($in['body']??'');
    $url=$in['url']??'#accueil';
    if(!$title||!$body){http_response_code(400);echo json_encode(['error'=>'Titre et message requis']);break;}
    try {
        $db=getDB();
        $st=$db->query("SELECT * FROM push_subscriptions");
        $subs=$st->fetchAll(PDO::FETCH_ASSOC);
        if(count($subs)===0){echo json_encode(['success'=>false,'error'=>'Aucun abonn\u00e9']);break;}
        $sent=0; $failed=0; $errors=[];
        $payload=['title'=>$title,'body'=>$body,'icon'=>'/logo.png','badge'=>'/logo.png','data'=>['url'=>$url]];
        foreach($subs as $sub){
            $subscription=['endpoint'=>$sub['endpoint'],'keys'=>['p256dh'=>$sub['p256dh'],'auth'=>$sub['auth']]];
            $result=sendWebPush($subscription,$payload);
            if($result['success']){ $sent++; }
            else {
                $failed++;
                $code=$result['code']??0;
                // Remove expired/invalid subscriptions
                if($code==404||$code==410){
                    $del=$db->prepare("DELETE FROM push_subscriptions WHERE id=:id");
                    $del->execute([':id'=>$sub['id']]);
                }
                $errors[]=['endpoint'=>substr($sub['endpoint'],-30),'code'=>$code,'error'=>$result['error']??''];
            }
        }
        echo json_encode(['success'=>true,'sent'=>$sent,'failed'=>$failed,'total'=>count($subs),'errors'=>array_slice($errors,0,5)]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

// ═══ MESSAGERIE ═══

case 'get_users':
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    try {
        $db=getDB(); $st=$db->prepare("SELECT id,display_name,role,player_id,parent_type FROM users ORDER BY display_name"); $st->execute();
        $users=[]; while($r=$st->fetch()){$users[]=['id'=>(int)$r['id'],'display_name'=>$r['display_name'],'role'=>$r['role'],'player_id'=>$r['player_id']?(int)$r['player_id']:null,'parent_type'=>$r['parent_type']];}
        echo json_encode(['success'=>true,'users'=>$users]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'send_message':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    // Rate limit: max 20 messages par heure
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'send_msg', 20, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de messages envoyés. Réessaye plus tard.']); break;
    }
    recordAttempt($clientIp, 'send_msg');
    $in=json_decode(file_get_contents('php://input'),true);
    $rid=(int)($in['recipient_id']??0);
    $playerId=(int)($in['player_id']??0);
    $subject=trim($in['subject']??''); $body=trim($in['body']??'');
    $msgType=$in['msg_type']??'general'; $parentMsgId=$in['parent_msg_id']??null;
    if(!$body){http_response_code(400);echo json_encode(['error'=>'Message requis']);break;}
    if(strlen($body)>10000) $body=substr($body,0,10000);
    if(strlen($subject)>255) $subject=substr($subject,0,255);
    if(!$rid && !$playerId){http_response_code(400);echo json_encode(['error'=>'Destinataire requis']);break;}
    if(!in_array($msgType,['general','convocation','gouter','lavage'])) $msgType='general';
    try {
        $db=getDB();
        $recipients=[];
        if($playerId && !$rid){
            // Find parent(s) of this player
            $st=$db->prepare("SELECT id,email FROM users WHERE player_id=:pid AND role='parent'");
            $st->execute([':pid'=>$playerId]);
            while($r=$st->fetch()) $recipients[]=$r;
            if(empty($recipients)){
                echo json_encode(['success'=>false,'error'=>'Aucun parent inscrit pour ce joueur. Le message ne peut pas être envoyé.']);
                break;
            }
        } else {
            $st=$db->prepare("SELECT id,email FROM users WHERE id=:id");
            $st->execute([':id'=>$rid]);
            $r=$st->fetch();
            if($r) $recipients[]=$r;
            else { http_response_code(404); echo json_encode(['error'=>'Destinataire non trouvé']); break; }
        }
        $sent=0;
        foreach($recipients as $rec){
            $st=$db->prepare("INSERT INTO messages (sender_id,recipient_id,subject,body,msg_type,parent_msg_id) VALUES(:s,:r,:sub,:b,:t,:p)");
            $st->execute([':s'=>$_SESSION['user_id'],':r'=>$rec['id'],':sub'=>$subject,':b'=>$body,':t'=>$msgType,':p'=>$parentMsgId]);
            if($rec['email']) sendEmailNotif($rec['email'],$subject?:'Nouveau message',nl2br(htmlspecialchars($body)));
            $sent++;
        }
        echo json_encode(['success'=>true,'messages_sent'=>$sent]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur envoi']);}
    break;

case 'get_inbox':
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT m.*,u.display_name AS sender_name,u.role AS sender_role FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.recipient_id=:uid ORDER BY m.created_at DESC LIMIT 100");
        $st->execute([':uid'=>$_SESSION['user_id']]);
        $msgs=[]; while($r=$st->fetch(PDO::FETCH_ASSOC)){
            $msgs[]=['id'=>(int)$r['id'],'sender_id'=>(int)$r['sender_id'],'sender_name'=>$r['sender_name'],'sender_role'=>$r['sender_role'],
                'subject'=>$r['subject'],'body'=>$r['body'],'msg_type'=>$r['msg_type'],'is_read'=>(int)$r['is_read'],
                'parent_msg_id'=>$r['parent_msg_id']?(int)$r['parent_msg_id']:null,'related_match_id'=>$r['related_match_id']?(int)$r['related_match_id']:null,'created_at'=>$r['created_at']];
        }
        echo json_encode(['success'=>true,'messages'=>$msgs]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'get_sent':
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    try {
        $db=getDB();
        $st=$db->prepare("SELECT m.*,u.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.recipient_id WHERE m.sender_id=:uid ORDER BY m.created_at DESC LIMIT 100");
        $st->execute([':uid'=>$_SESSION['user_id']]);
        $msgs=[]; while($r=$st->fetch(PDO::FETCH_ASSOC)){
            $msgs[]=['id'=>(int)$r['id'],'recipient_id'=>(int)$r['recipient_id'],'recipient_name'=>$r['recipient_name'],
                'subject'=>$r['subject'],'body'=>$r['body'],'msg_type'=>$r['msg_type'],'is_read'=>(int)$r['is_read'],'related_match_id'=>$r['related_match_id']?(int)$r['related_match_id']:null,'created_at'=>$r['created_at']];
        }
        echo json_encode(['success'=>true,'messages'=>$msgs]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'mark_read':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    $in=json_decode(file_get_contents('php://input'),true); $msgId=(int)($in['message_id']??0);
    try {
        $db=getDB(); $st=$db->prepare("UPDATE messages SET is_read=1 WHERE id=:id AND recipient_id=:uid");
        $st->execute([':id'=>$msgId,':uid'=>$_SESSION['user_id']]);
        echo json_encode(['success'=>true]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'get_thread':
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    $threadId=(int)($_GET['thread_id']??0);
    if(!$threadId){http_response_code(400);echo json_encode(['error'=>'thread_id requis']);break;}
    try {
        $db=getDB(); $uid=(int)$_SESSION['user_id'];
        // Get all messages in thread: root + all replies
        $st=$db->prepare("SELECT m.*,u.display_name AS sender_name,u.role AS sender_role FROM messages m JOIN users u ON u.id=m.sender_id WHERE (m.id=:tid OR m.parent_msg_id=:tid2) AND (m.sender_id=:uid1 OR m.recipient_id=:uid2) ORDER BY m.created_at ASC");
        $st->execute([':tid'=>$threadId,':tid2'=>$threadId,':uid1'=>$uid,':uid2'=>$uid]);
        $msgs=[];
        while($r=$st->fetch(PDO::FETCH_ASSOC)){
            $msgs[]=['id'=>(int)$r['id'],'sender_id'=>(int)$r['sender_id'],'recipient_id'=>(int)$r['recipient_id'],
                'sender_name'=>$r['sender_name'],'sender_role'=>$r['sender_role'],
                'subject'=>$r['subject'],'body'=>$r['body'],'msg_type'=>$r['msg_type'],'is_read'=>(int)$r['is_read'],
                'parent_msg_id'=>$r['parent_msg_id']?(int)$r['parent_msg_id']:null,'related_match_id'=>$r['related_match_id']?(int)$r['related_match_id']:null,'created_at'=>$r['created_at']];
        }
        // Mark all unread messages in this thread as read
        $st2=$db->prepare("UPDATE messages SET is_read=1 WHERE (id=:tid3 OR parent_msg_id=:tid4) AND recipient_id=:uid3 AND is_read=0");
        $st2->execute([':tid3'=>$threadId,':tid4'=>$threadId,':uid3'=>$uid]);
        echo json_encode(['success'=>true,'messages'=>$msgs]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'delete_thread':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['user_id'])){http_response_code(401);echo json_encode(['error'=>'Non connecté']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $threadId=(int)($in['thread_id']??0);
    if(!$threadId){http_response_code(400);echo json_encode(['error'=>'thread_id requis']);break;}
    try {
        $db=getDB(); $uid=(int)$_SESSION['user_id'];
        $st=$db->prepare("DELETE FROM messages WHERE (id=:tid OR parent_msg_id=:tid2) AND (sender_id=:uid1 OR recipient_id=:uid2)");
        $st->execute([':tid'=>$threadId,':tid2'=>$threadId,':uid1'=>$uid,':uid2'=>$uid]);
        echo json_encode(['success'=>true,'deleted'=>$st->rowCount()]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'unread_count':
    if(!isset($_SESSION['user_id'])){echo json_encode(['count'=>0]);break;}
    try {
        $db=getDB(); $st=$db->prepare("SELECT COUNT(*) as c FROM messages WHERE recipient_id=:uid AND is_read=0");
        $st->execute([':uid'=>$_SESSION['user_id']]); $r=$st->fetch();
        echo json_encode(['count'=>(int)$r['c']]);
    } catch(Exception $e){echo json_encode(['count'=>0]);}
    break;

// ═══ CONVOCATIONS ═══

case 'save_convocations':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $matchId=$in['match_id']??''; $matchLabel=$in['match_label']??'Prochain match'; $players=$in['players']??[];
    $matchHeure=$in['match_heure']??''; $matchGymnase=$in['match_gymnase']??''; $matchLieu=$in['match_lieu']??'';
    $matchHeureRdv=$in['match_heure_rdv']??'';
    $gouterSpecial=$in['gouter_special']??null; // "coach" or "ext"
    // Try to get extras from DB (overrides frontend if set)
    try {
        $dbe=getDB(); $ste=$dbe->prepare("SELECT gymnase,heure_rdv FROM match_extras WHERE match_id=:mid"); $ste->execute([':mid'=>$matchId]); $ext=$ste->fetch();
        if($ext){ if($ext['gymnase']) $matchGymnase=$ext['gymnase']; if($ext['heure_rdv']) $matchHeureRdv=$ext['heure_rdv']; }
    } catch(Exception $e){}
    if(!$matchId||!is_array($players)){http_response_code(400);echo json_encode(['error'=>'Données invalides']);break;}
    try {
        $db=getDB(); $coachId=$_SESSION['user_id']; $sent=0;
        // Store gouter_special as player_id=0 row (1=coach, 2=ext)
        $gSpecialVal = $gouterSpecial==='coach' ? 1 : ($gouterSpecial==='ext' ? 2 : 0);
        $st=$db->prepare("INSERT INTO convocations (match_id,player_id,convoked,gouter,lavage) VALUES(:mid,0,0,:g,0) ON DUPLICATE KEY UPDATE gouter=:g2,updated_at=CURRENT_TIMESTAMP");
        $st->execute([':mid'=>$matchId,':g'=>$gSpecialVal,':g2'=>$gSpecialVal]);
        foreach($players as $p){
            $pid=(int)($p['player_id']??0); $conv=(int)($p['convoked']??0);
            $gout=(int)($p['gouter']??0); $lav=(int)($p['lavage']??0);
            if(!$pid) continue;
            $st=$db->prepare("INSERT INTO convocations (match_id,player_id,convoked,gouter,lavage) VALUES(:mid,:pid,:c,:g,:l) ON DUPLICATE KEY UPDATE convoked=:c2,gouter=:g2,lavage=:l2,updated_at=CURRENT_TIMESTAMP");
            $st->execute([':mid'=>$matchId,':pid'=>$pid,':c'=>$conv,':g'=>$gout,':l'=>$lav,':c2'=>$conv,':g2'=>$gout,':l2'=>$lav]);
            if($conv){
                $st2=$db->prepare("SELECT id,email,display_name FROM users WHERE player_id=:pid AND role='parent'");
                $st2->execute([':pid'=>$pid]);
                while($parent=$st2->fetch()){
                    $pName=$p['player_name']??'votre enfant';
                    $body="Bonjour ! 🏀\n\n$pName est convoqué(e) pour le match : $matchLabel.\n\n";
                    if($matchHeureRdv) $body.="⏰ RDV : $matchHeureRdv\n";
                    if($matchHeure) $body.="🕐 Coup d'envoi : $matchHeure\n";
                    if($matchGymnase) $body.="🏟️ Gymnase : $matchGymnase\n";
                    elseif($matchLieu) $body.="📍 Lieu : $matchLieu\n";
                    if($matchHeure || $matchGymnase || $matchLieu || $matchHeureRdv) $body.="\n";
                    if($gout) $body.="🍪 Goûter : Merci de prévoir le goûter pour l'équipe.\n\n";
                    if($lav) $body.="👕 Lavage des maillots : Merci de laver les maillots après ce match.\n\n";
                    $body.="Merci et à bientôt !\nCoach Alex";
                    $sub="Convocation : $matchLabel";
                    $st3=$db->prepare("INSERT INTO messages (sender_id,recipient_id,subject,body,msg_type,related_match_id) VALUES(:s,:r,:sub,:b,'convocation',:mid)");
                    $st3->execute([':s'=>$coachId,':r'=>$parent['id'],':sub'=>$sub,':b'=>$body,':mid'=>$matchId]);
                    if($parent['email']) sendEmailNotif($parent['email'],$sub,nl2br(htmlspecialchars($body)));
                    $sent++;
                }
            }
        }
        echo json_encode(['success'=>true,'messages_sent'=>$sent]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'get_convocations':
    $matchId=$_GET['match_id']??'';
    if(!$matchId){http_response_code(400);echo json_encode(['error'=>'match_id requis']);break;}
    try {
        $db=getDB(); $st=$db->prepare("SELECT player_id,convoked,gouter,lavage FROM convocations WHERE match_id=:mid");
        $st->execute([':mid'=>$matchId]);
        $convs=[]; $gouterSpecial=null;
        while($r=$st->fetch()){
            $pid=(int)$r['player_id'];
            if($pid===0){ // special gouter row
                $gv=(int)$r['gouter'];
                if($gv===1) $gouterSpecial='coach';
                elseif($gv===2) $gouterSpecial='ext';
                continue;
            }
            $convs[$pid]=['convoked'=>(int)$r['convoked'],'gouter'=>(int)$r['gouter'],'lavage'=>(int)$r['lavage']];
        }
        echo json_encode(['success'=>true,'convocations'=>$convs,'gouter_special'=>$gouterSpecial]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

// ═══ PHOTOS ═══

case 'get_photos':
    $matchId=$_GET['match_id']??'';
    if(!$matchId){http_response_code(400);echo json_encode(['error'=>'match_id requis']);break;}
    try {
        $db=getDB(); $st=$db->prepare("SELECT id,slot,filename FROM match_photos WHERE match_id=:mid ORDER BY slot ASC");
        $st->execute([':mid'=>$matchId]);
        $photos=[]; while($r=$st->fetch()){$photos[]=['id'=>$r['id'],'slot'=>$r['slot'],'url'=>'uploads/'.$r['filename']];}
        echo json_encode(['success'=>true,'photos'=>$photos]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'upload_photo':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $matchId=$_POST['match_id']??''; $slot=$_POST['slot']??'';
    if(!$matchId||!in_array($slot,['left','right'])){http_response_code(400);echo json_encode(['error'=>'match_id et slot requis']);break;}
    if(!isset($_FILES['photo'])||$_FILES['photo']['error']!==UPLOAD_ERR_OK){http_response_code(400);echo json_encode(['error'=>'Aucun fichier']);break;}
    $file=$_FILES['photo'];
    if($file['size']>5*1024*1024){http_response_code(400);echo json_encode(['error'=>'Max 5 Mo']);break;}
    $allowed=['image/jpeg','image/png','image/webp','image/gif'];
    $finfo=finfo_open(FILEINFO_MIME_TYPE); $mime=finfo_file($finfo,$file['tmp_name']); finfo_close($finfo);
    if(!in_array($mime,$allowed)){http_response_code(400);echo json_encode(['error'=>'Type non autorisé']);break;}
    $dir=__DIR__.'/uploads/'; if(!is_dir($dir)) mkdir($dir,0755,true);
    $ext=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','image/gif'=>'gif'][$mime];
    $fn='match_'.$matchId.'_'.$slot.'_'.time().'.'.$ext;
    if(!move_uploaded_file($file['tmp_name'],$dir.$fn)){http_response_code(500);echo json_encode(['error'=>'Erreur upload']);break;}
    try {
        $db=getDB(); $st=$db->prepare("SELECT filename FROM match_photos WHERE match_id=:mid AND slot=:s"); $st->execute([':mid'=>$matchId,':s'=>$slot]);
        $old=$st->fetch(); if($old && file_exists($dir.$old['filename'])) unlink($dir.$old['filename']);
        $st=$db->prepare("INSERT INTO match_photos (match_id,slot,filename) VALUES(:mid,:s,:f) ON DUPLICATE KEY UPDATE filename=:f2,updated_at=CURRENT_TIMESTAMP");
        $st->execute([':mid'=>$matchId,':s'=>$slot,':f'=>$fn,':f2'=>$fn]);
        echo json_encode(['success'=>true,'url'=>'uploads/'.$fn]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur BDD']);}
    break;

case 'delete_photo':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true); $photoId=$in['photo_id']??0;
    try {
        $db=getDB(); $st=$db->prepare("SELECT filename FROM match_photos WHERE id=:id"); $st->execute([':id'=>$photoId]); $ph=$st->fetch();
        if($ph){ $f=__DIR__.'/uploads/'.$ph['filename']; if(file_exists($f)) unlink($f);
            $st=$db->prepare("DELETE FROM match_photos WHERE id=:id"); $st->execute([':id'=>$photoId]);
            echo json_encode(['success'=>true]);
        } else {http_response_code(404);echo json_encode(['error'=>'Non trouvé']);}
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

// ═══ MATCH EXTRAS (gymnase, heure rdv, feuille) ═══

case 'get_match_extras':
    $matchId=$_GET['match_id']??'';
    if(!$matchId){http_response_code(400);echo json_encode(['error'=>'match_id requis']);break;}
    try {
        $db=getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS match_extras (
            match_id INT PRIMARY KEY,
            gymnase VARCHAR(255) DEFAULT '',
            heure_rdv VARCHAR(20) DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        $st=$db->prepare("SELECT * FROM match_extras WHERE match_id=:mid"); $st->execute([':mid'=>$matchId]);
        $row=$st->fetch();
        // Also get sheet photo
        $st2=$db->prepare("SELECT id,filename FROM match_photos WHERE match_id=:mid AND slot='sheet'"); $st2->execute([':mid'=>$matchId]);
        $sheet=$st2->fetch();
        echo json_encode([
            'success'=>true,
            'gymnase'=>$row?$row['gymnase']:'',
            'heure_rdv'=>$row?$row['heure_rdv']:'',
            'sheet'=>$sheet?['id'=>(int)$sheet['id'],'url'=>'uploads/'.$sheet['filename']]:null
        ]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'save_match_extras':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true);
    $matchId=(int)($in['match_id']??0); $gymnase=trim($in['gymnase']??''); $heureRdv=trim($in['heure_rdv']??'');
    if(!$matchId){http_response_code(400);echo json_encode(['error'=>'match_id requis']);break;}
    try {
        $db=getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS match_extras (
            match_id INT PRIMARY KEY,
            gymnase VARCHAR(255) DEFAULT '',
            heure_rdv VARCHAR(20) DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        $st=$db->prepare("INSERT INTO match_extras (match_id,gymnase,heure_rdv) VALUES(:mid,:g,:h) ON DUPLICATE KEY UPDATE gymnase=:g2,heure_rdv=:h2");
        $st->execute([':mid'=>$matchId,':g'=>$gymnase,':h'=>$heureRdv,':g2'=>$gymnase,':h2'=>$heureRdv]);
        echo json_encode(['success'=>true]);

        // ═══ Email notification aux parents ═══
        if ($gymnase || $heureRdv) {
            $html = "<p>✏️ <strong>Infos match mises à jour</strong></p>";
            if ($heureRdv) $html .= "<p>⏰ Heure de RDV : <strong>$heureRdv</strong></p>";
            if ($gymnase) $html .= "<p>🏟️ Gymnase : <strong>$gymnase</strong></p>";
            $html .= "<p style='margin-top:16px'><a href='https://espeu9.fr/#matchs' style='display:inline-block;background:#1a6b2e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold'>Voir le match →</a></p>";
            notifyAllParents("Infos match mises à jour", $html);
        }
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

case 'upload_match_sheet':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $matchId=$_POST['match_id']??'';
    if(!$matchId){http_response_code(400);echo json_encode(['error'=>'match_id requis']);break;}
    if(!isset($_FILES['sheet'])||$_FILES['sheet']['error']!==UPLOAD_ERR_OK){
        http_response_code(400);echo json_encode(['error'=>'Aucun fichier reçu ou erreur upload']);break;
    }
    $file=$_FILES['sheet'];
    if($file['size']>10*1024*1024){http_response_code(400);echo json_encode(['error'=>'Max 10 Mo']);break;}
    $allowed=['image/jpeg','image/png','image/webp','application/pdf'];
    $finfo=finfo_open(FILEINFO_MIME_TYPE); $mime=finfo_file($finfo,$file['tmp_name']); finfo_close($finfo);
    if(!in_array($mime,$allowed)){http_response_code(400);echo json_encode(['error'=>'Type non autorisé (JPG, PNG, PDF uniquement)']);break;}
    $dir=__DIR__.'/uploads/'; if(!is_dir($dir)) mkdir($dir,0755,true);
    $exts=['image/jpeg'=>'jpg','image/png'=>'png','image/webp'=>'webp','application/pdf'=>'pdf'];
    $ext=$exts[$mime]??'jpg';
    $fn='sheet_'.$matchId.'_'.time().'.'.$ext;
    if(!move_uploaded_file($file['tmp_name'],$dir.$fn)){http_response_code(500);echo json_encode(['error'=>'Erreur déplacement fichier']);break;}
    try {
        $db=getDB();
        // Auto-create table if not exists
        $db->exec("CREATE TABLE IF NOT EXISTS match_photos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            match_id INT NOT NULL,
            slot VARCHAR(20) NOT NULL DEFAULT 'photo',
            filename VARCHAR(255) NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_match_slot (match_id, slot)
        )");
        $st=$db->prepare("SELECT filename FROM match_photos WHERE match_id=:mid AND slot='sheet'"); $st->execute([':mid'=>$matchId]);
        $old=$st->fetch(); if($old && file_exists($dir.$old['filename'])) unlink($dir.$old['filename']);
        $st=$db->prepare("INSERT INTO match_photos (match_id,slot,filename) VALUES(:mid,'sheet',:f) ON DUPLICATE KEY UPDATE filename=:f2,updated_at=CURRENT_TIMESTAMP");
        $st->execute([':mid'=>$matchId,':f'=>$fn,':f2'=>$fn]);
        // Return the sheet id too
        $st3=$db->prepare("SELECT id FROM match_photos WHERE match_id=:mid AND slot='sheet'"); $st3->execute([':mid'=>$matchId]);
        $row3=$st3->fetch();
        echo json_encode(['success'=>true,'url'=>'uploads/'.$fn,'sheet_id'=>$row3?(int)$row3['id']:0]);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur BDD']);}
    break;

case 'delete_match_sheet':
    if($_SERVER['REQUEST_METHOD']!=='POST'){http_response_code(405);echo json_encode(['error'=>'POST requis']);break;}
    if(!isset($_SESSION['role'])||$_SESSION['role']!=='coach'){http_response_code(403);echo json_encode(['error'=>'Coach requis']);break;}
    $in=json_decode(file_get_contents('php://input'),true); $sheetId=(int)($in['sheet_id']??0);
    try {
        $db=getDB(); $st=$db->prepare("SELECT filename FROM match_photos WHERE id=:id AND slot='sheet'"); $st->execute([':id'=>$sheetId]); $ph=$st->fetch();
        if($ph){ $f=__DIR__.'/uploads/'.$ph['filename']; if(file_exists($f)) unlink($f);
            $st=$db->prepare("DELETE FROM match_photos WHERE id=:id"); $st->execute([':id'=>$sheetId]);
            echo json_encode(['success'=>true]);
        } else {http_response_code(404);echo json_encode(['error'=>'Non trouvé']);}
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur']);}
    break;

case 'setup':
    // Rate limit setup attempts
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'setup', 3, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de tentatives']); break;
    }
    recordAttempt($clientIp, 'setup');
    try {
        $db=getDB(); $st=$db->prepare("SELECT COUNT(*) as c FROM users WHERE username='coach'"); $st->execute(); $r=$st->fetch();
        if($r['c']>0){echo json_encode(['success'=>true,'message'=>'Déjà configuré']);break;}
        $hash=password_hash(COACH_PIN,PASSWORD_DEFAULT);
        $st=$db->prepare("INSERT INTO users (username,password_hash,display_name,role) VALUES('coach',:p,'Coach Alex','coach')");
        $st->execute([':p'=>$hash]);
        echo json_encode(['success'=>true,'message'=>'Configuration effectuée']);
    } catch(Exception $e){http_response_code(500);echo json_encode(['error'=>'Erreur serveur']);}
    break;

// ═══ ANALYSE IA — FEUILLE DE MATCH ═══

case 'analyze_match_sheet':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'POST requis']); break; }
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') { http_response_code(403); echo json_encode(['error' => 'Coach requis']); break; }
    // Rate limit: max 10 scans IA par heure
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'ai_scan', 10, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de scans IA. Réessaye dans 1 heure.']); break;
    }
    recordAttempt($clientIp, 'ai_scan');
    if (!defined('CLAUDE_API_KEY') || !CLAUDE_API_KEY) { http_response_code(500); echo json_encode(['error' => 'Clé API Claude non configurée']); break; }
    if (!isset($_FILES['pdf']) || $_FILES['pdf']['error'] !== UPLOAD_ERR_OK) { http_response_code(400); echo json_encode(['error' => 'Fichier PDF requis']); break; }
    $file = $_FILES['pdf'];
    if ($file['size'] > 15 * 1024 * 1024) { http_response_code(400); echo json_encode(['error' => 'Max 15 Mo']); break; }
    // Lire et convertir en base64
    $pdfData = file_get_contents($file['tmp_name']);
    $base64 = base64_encode($pdfData);
    // Déterminer le type MIME
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $isImage = in_array($mime, ['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
    $isPdf = ($mime === 'application/pdf');
    if (!$isImage && !$isPdf) { http_response_code(400); echo json_encode(['error' => 'Format non supporté. Envoie un PDF ou une image (JPG, PNG).']); break; }

    // Construire le contenu pour Claude
    $docContent = $isImage ? [
        'type' => 'image',
        'source' => ['type' => 'base64', 'media_type' => $mime, 'data' => $base64]
    ] : [
        'type' => 'document',
        'source' => ['type' => 'base64', 'media_type' => 'application/pdf', 'data' => $base64]
    ];

    $prompt = <<<'PROMPT'
Analyse cette feuille de match de basketball (catégorie U9/U11 en France — FFBB).

Extrais TOUTES les informations et renvoie UNIQUEMENT un objet JSON valide (sans markdown, sans backticks, sans texte avant/après).

Voici le format JSON exact attendu :
{
  "journee": 1,
  "date": "06/12/2025",
  "heure": "10:30",
  "lieu": "Nom de la ville",
  "domExt": "dom",
  "equipeA": {
    "nom": "Nom complet équipe domicile",
    "short": "NOM COURT",
    "score": 40
  },
  "equipeB": {
    "nom": "Nom complet équipe extérieur",
    "short": "NOM COURT",
    "score": 20
  },
  "scores": {
    "qt1": {"a": 10, "b": 5},
    "qt2": {"a": 12, "b": 6},
    "qt3": {"a": 8, "b": 4},
    "qt4": {"a": 10, "b": 5}
  },
  "espeStats": [
    {"num": 6, "nom": "NOM Prénom", "min": "15:06", "pts": 2, "tirs": 1, "t3": 0, "t2i": 1, "t2e": 0, "lf": 0, "fautes": 0}
  ],
  "advStats": [
    {"num": 4, "nom": "NOM Prénom", "min": "09:20", "pts": 0, "tirs": 0, "t3": 0, "t2i": 0, "t2e": 0, "lf": 0, "fautes": 0}
  ]
}

RÈGLES IMPORTANTES :
- L'équipe ESPE (ou "ESPE Basket Châlons", "EBCCA", "Châlons") : mets son short à "ESPE"
- domExt : "dom" si ESPE joue à domicile (Châlons-en-Champagne), "ext" si à l'extérieur
- equipeA = équipe qui reçoit (domicile), equipeB = équipe visiteur (extérieur)
- scores.qt1.a = score equipeA au QT1, scores.qt1.b = score equipeB au QT1
- "tirs" = nombre total de tirs réussis (paniers marqués)
- "t2i" = tirs à 2 points réussis dans la raquette
- "t2e" = tirs à 2 points réussis hors raquette
- "t3" = tirs à 3 points réussis
- "lf" = lancers francs réussis
- "fautes" = nombre de fautes personnelles
- "min" = temps de jeu au format "MM:SS"
- Si une donnée est illisible ou absente, mets 0 ou "00:00"
- Les noms doivent être en format "NOM Prénom" (majuscules pour le nom de famille)
- Renvoie UNIQUEMENT le JSON, rien d'autre
PROMPT;

    // Appel API Claude
    $payload = json_encode([
        'model' => 'claude-sonnet-4-20250514',
        'max_tokens' => 4000,
        'messages' => [
            [
                'role' => 'user',
                'content' => [
                    $docContent,
                    ['type' => 'text', 'text' => $prompt]
                ]
            ]
        ]
    ]);

    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'x-api-key: ' . CLAUDE_API_KEY,
            'anthropic-version: 2023-06-01'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        http_response_code(500);
        echo json_encode(['error' => 'Erreur réseau vers Claude API: ' . $curlError]);
        break;
    }
    if ($httpCode !== 200) {
        $errData = json_decode($response, true);
        $errMsg = $errData['error']['message'] ?? 'Erreur API Claude (HTTP ' . $httpCode . ')';
        http_response_code(500);
        echo json_encode(['error' => $errMsg, 'http_code' => $httpCode]);
        break;
    }

    $result = json_decode($response, true);
    $textContent = '';
    foreach (($result['content'] ?? []) as $block) {
        if (($block['type'] ?? '') === 'text') $textContent .= $block['text'];
    }

    // Nettoyer le JSON (enlever backticks markdown si présents)
    $textContent = trim($textContent);
    $textContent = preg_replace('/^```json\s*/i', '', $textContent);
    $textContent = preg_replace('/\s*```$/i', '', $textContent);
    $textContent = trim($textContent);

    $matchData = json_decode($textContent, true);
    if (!$matchData) {
        http_response_code(500);
        echo json_encode(['error' => 'Impossible de parser la réponse IA', 'raw' => substr($textContent, 0, 500)]);
        break;
    }

    // Calculer espeScore / advScore / win
    $eqAShort = $matchData['equipeA']['short'] ?? '';
    $eqBShort = $matchData['equipeB']['short'] ?? '';
    if (strtoupper($eqAShort) === 'ESPE') {
        $matchData['espeScore'] = (int)($matchData['equipeA']['score'] ?? 0);
        $matchData['advScore'] = (int)($matchData['equipeB']['score'] ?? 0);
    } else {
        $matchData['espeScore'] = (int)($matchData['equipeB']['score'] ?? 0);
        $matchData['advScore'] = (int)($matchData['equipeA']['score'] ?? 0);
    }
    $matchData['win'] = $matchData['espeScore'] > $matchData['advScore'];

    echo json_encode(['success' => true, 'matchData' => $matchData]);
    break;

// ═══ RÉPONSES PRÉSENCE / ABSENCE AUX CONVOCATIONS ═══

case 'respond_convocation':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'POST requis']); break; }
    if (!isset($_SESSION['user_id'])) { http_response_code(401); echo json_encode(['error' => 'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    $playerId = (int)($in['player_id'] ?? 0);
    $response = $in['response'] ?? '';
    if (!$matchId || !$playerId || !in_array($response, ['present', 'absent', 'attente'])) {
        http_response_code(400); echo json_encode(['error' => 'Données invalides']); break;
    }
    // Vérifier que l'utilisateur est parent de ce joueur OU coach
    $uid = (int)$_SESSION['user_id'];
    $role = $_SESSION['role'] ?? '';
    if ($role !== 'coach') {
        $userPid = $_SESSION['player_id'] ?? null;
        if ((int)$userPid !== $playerId) {
            http_response_code(403); echo json_encode(['error' => 'Pas autorisé pour ce joueur']); break;
        }
    }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS convocation_responses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            match_id INT NOT NULL,
            player_id INT NOT NULL,
            user_id INT NOT NULL,
            response ENUM('present','absent','attente') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_response (match_id, player_id)
        )");
        // Mettre à jour l'ENUM si la table existait déjà sans 'attente'
        try { $db->exec("ALTER TABLE convocation_responses MODIFY COLUMN response ENUM('present','absent','attente') NOT NULL"); } catch(Exception $e2) {}
        $st = $db->prepare("INSERT INTO convocation_responses (match_id, player_id, user_id, response) VALUES (:mid, :pid, :uid, :r) ON DUPLICATE KEY UPDATE response = :r2, user_id = :uid2, updated_at = CURRENT_TIMESTAMP");
        $st->execute([':mid' => $matchId, ':pid' => $playerId, ':uid' => $uid, ':r' => $response, ':r2' => $response, ':uid2' => $uid]);
        echo json_encode(['success' => true, 'response' => $response]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

case 'get_convocation_responses':
    $matchId = (int)($_GET['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error' => 'match_id requis']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS convocation_responses (
            id INT AUTO_INCREMENT PRIMARY KEY,
            match_id INT NOT NULL,
            player_id INT NOT NULL,
            user_id INT NOT NULL,
            response ENUM('present','absent','attente') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_response (match_id, player_id)
        )");
        // Mettre à jour l'ENUM si la table existait déjà sans 'attente'
        try { $db->exec("ALTER TABLE convocation_responses MODIFY COLUMN response ENUM('present','absent','attente') NOT NULL"); } catch(Exception $e2) {}
        $st = $db->prepare("SELECT player_id, response, updated_at FROM convocation_responses WHERE match_id = :mid");
        $st->execute([':mid' => $matchId]);
        $responses = [];
        while ($r = $st->fetch()) {
            $responses[(int)$r['player_id']] = ['response' => $r['response'], 'date' => $r['updated_at']];
        }
        echo json_encode(['success' => true, 'responses' => $responses]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

// ═══ MATCHS EN BASE DE DONNÉES ═══

case 'get_matches':
    try {
        $db = getDB();
        // Vérifier si la table existe
        $tableCheck = $db->query("SHOW TABLES LIKE 'match_results'");
        if ($tableCheck->rowCount() === 0) {
            echo json_encode(['success' => true, 'matches' => []]);
            break;
        }
        $st = $db->query("SELECT * FROM match_results ORDER BY id ASC");
        $matches = [];
        while ($m = $st->fetch()) {
            // Récupérer les stats ESPE
            $st2 = $db->prepare("SELECT num, nom, minutes AS min, pts, tirs, t3, t2i, t2e, lf, fautes FROM match_player_stats WHERE match_id = :mid AND team_type = 'espe' ORDER BY num ASC");
            $st2->execute([':mid' => $m['id']]);
            $espeStats = $st2->fetchAll(PDO::FETCH_ASSOC);
            foreach ($espeStats as &$s) { $s['num'] = (int)$s['num']; $s['pts'] = (int)$s['pts']; $s['tirs'] = (int)$s['tirs']; $s['t3'] = (int)$s['t3']; $s['t2i'] = (int)$s['t2i']; $s['t2e'] = (int)$s['t2e']; $s['lf'] = (int)$s['lf']; $s['fautes'] = (int)$s['fautes']; }
            // Récupérer les stats adversaire
            $st3 = $db->prepare("SELECT num, nom, minutes AS min, pts, tirs, t3, t2i, t2e, lf, fautes FROM match_player_stats WHERE match_id = :mid AND team_type = 'adv' ORDER BY num ASC");
            $st3->execute([':mid' => $m['id']]);
            $advStats = $st3->fetchAll(PDO::FETCH_ASSOC);
            foreach ($advStats as &$s) { $s['num'] = (int)$s['num']; $s['pts'] = (int)$s['pts']; $s['tirs'] = (int)$s['tirs']; $s['t3'] = (int)$s['t3']; $s['t2i'] = (int)$s['t2i']; $s['t2e'] = (int)$s['t2e']; $s['lf'] = (int)$s['lf']; $s['fautes'] = (int)$s['fautes']; }
            $matches[] = [
                'id' => (int)$m['id'],
                'journee' => (int)$m['journee'],
                'date' => $m['date'],
                'heure' => $m['heure'],
                'lieu' => $m['lieu'],
                'domExt' => $m['dom_ext'],
                'equipeA' => ['nom' => $m['equipe_a_nom'], 'short' => $m['equipe_a_short'], 'score' => (int)$m['equipe_a_score']],
                'equipeB' => ['nom' => $m['equipe_b_nom'], 'short' => $m['equipe_b_short'], 'score' => (int)$m['equipe_b_score']],
                'espeScore' => (int)$m['espe_score'],
                'advScore' => (int)$m['adv_score'],
                'win' => (bool)$m['win'],
                'scores' => [
                    'qt1' => ['a' => (int)$m['qt1_a'], 'b' => (int)$m['qt1_b']],
                    'qt2' => ['a' => (int)$m['qt2_a'], 'b' => (int)$m['qt2_b']],
                    'qt3' => ['a' => (int)$m['qt3_a'], 'b' => (int)$m['qt3_b']],
                    'qt4' => ['a' => (int)$m['qt4_a'], 'b' => (int)$m['qt4_b']]
                ],
                'espeStats' => $espeStats,
                'advStats' => $advStats
            ];
        }
        echo json_encode(['success' => true, 'matches' => $matches]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

case 'save_match':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'POST requis']); break; }
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') { http_response_code(403); echo json_encode(['error' => 'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $journee = (int)($in['journee'] ?? 0);
    $date = trim($in['date'] ?? '');
    $heure = trim($in['heure'] ?? '');
    $lieu = trim($in['lieu'] ?? '');
    $domExt = $in['domExt'] ?? 'dom';
    $eqA = $in['equipeA'] ?? [];
    $eqB = $in['equipeB'] ?? [];
    $scores = $in['scores'] ?? [];
    $espeStats = $in['espeStats'] ?? [];
    $advStats = $in['advStats'] ?? [];
    $matchId = (int)($in['id'] ?? 0); // 0 = nouveau, >0 = mise à jour
    $isNewMatch = ($matchId === 0);
    if (!$journee || !$date) { http_response_code(400); echo json_encode(['error' => 'Journée et date requis']); break; }
    if (!in_array($domExt, ['dom', 'ext'])) $domExt = 'dom';
    // Calculer espeScore, advScore, win
    $espeScore = ($eqA['short'] ?? '') === 'ESPE' ? (int)($eqA['score'] ?? 0) : (int)($eqB['score'] ?? 0);
    $advScore = ($eqA['short'] ?? '') === 'ESPE' ? (int)($eqB['score'] ?? 0) : (int)($eqA['score'] ?? 0);
    $win = $espeScore > $advScore ? 1 : 0;
    try {
        $db = getDB();
        if ($matchId > 0) {
            // Mise à jour
            $st = $db->prepare("UPDATE match_results SET journee=:j, date=:d, heure=:h, lieu=:l, dom_ext=:de, equipe_a_nom=:ean, equipe_a_short=:eas, equipe_a_score=:easc, equipe_b_nom=:ebn, equipe_b_short=:ebs, equipe_b_score=:ebsc, espe_score=:es, adv_score=:as2, win=:w, qt1_a=:q1a, qt1_b=:q1b, qt2_a=:q2a, qt2_b=:q2b, qt3_a=:q3a, qt3_b=:q3b, qt4_a=:q4a, qt4_b=:q4b WHERE id=:id");
            $st->execute([
                ':j' => $journee, ':d' => $date, ':h' => $heure, ':l' => $lieu, ':de' => $domExt,
                ':ean' => $eqA['nom'] ?? '', ':eas' => $eqA['short'] ?? '', ':easc' => (int)($eqA['score'] ?? 0),
                ':ebn' => $eqB['nom'] ?? '', ':ebs' => $eqB['short'] ?? '', ':ebsc' => (int)($eqB['score'] ?? 0),
                ':es' => $espeScore, ':as2' => $advScore, ':w' => $win,
                ':q1a' => (int)($scores['qt1']['a'] ?? 0), ':q1b' => (int)($scores['qt1']['b'] ?? 0),
                ':q2a' => (int)($scores['qt2']['a'] ?? 0), ':q2b' => (int)($scores['qt2']['b'] ?? 0),
                ':q3a' => (int)($scores['qt3']['a'] ?? 0), ':q3b' => (int)($scores['qt3']['b'] ?? 0),
                ':q4a' => (int)($scores['qt4']['a'] ?? 0), ':q4b' => (int)($scores['qt4']['b'] ?? 0),
                ':id' => $matchId
            ]);
            // Supprimer anciennes stats puis réinsérer
            $db->prepare("DELETE FROM match_player_stats WHERE match_id = :mid")->execute([':mid' => $matchId]);
        } else {
            // Nouveau match
            $st = $db->prepare("INSERT INTO match_results (journee, date, heure, lieu, dom_ext, equipe_a_nom, equipe_a_short, equipe_a_score, equipe_b_nom, equipe_b_short, equipe_b_score, espe_score, adv_score, win, qt1_a, qt1_b, qt2_a, qt2_b, qt3_a, qt3_b, qt4_a, qt4_b) VALUES (:j, :d, :h, :l, :de, :ean, :eas, :easc, :ebn, :ebs, :ebsc, :es, :as2, :w, :q1a, :q1b, :q2a, :q2b, :q3a, :q3b, :q4a, :q4b)");
            $st->execute([
                ':j' => $journee, ':d' => $date, ':h' => $heure, ':l' => $lieu, ':de' => $domExt,
                ':ean' => $eqA['nom'] ?? '', ':eas' => $eqA['short'] ?? '', ':easc' => (int)($eqA['score'] ?? 0),
                ':ebn' => $eqB['nom'] ?? '', ':ebs' => $eqB['short'] ?? '', ':ebsc' => (int)($eqB['score'] ?? 0),
                ':es' => $espeScore, ':as2' => $advScore, ':w' => $win,
                ':q1a' => (int)($scores['qt1']['a'] ?? 0), ':q1b' => (int)($scores['qt1']['b'] ?? 0),
                ':q2a' => (int)($scores['qt2']['a'] ?? 0), ':q2b' => (int)($scores['qt2']['b'] ?? 0),
                ':q3a' => (int)($scores['qt3']['a'] ?? 0), ':q3b' => (int)($scores['qt3']['b'] ?? 0),
                ':q4a' => (int)($scores['qt4']['a'] ?? 0), ':q4b' => (int)($scores['qt4']['b'] ?? 0)
            ]);
            $matchId = (int)$db->lastInsertId();
        }
        // Insérer stats joueurs ESPE
        $stIns = $db->prepare("INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES (:mid, :tt, :n, :nom, :min, :pts, :tirs, :t3, :t2i, :t2e, :lf, :f)");
        foreach ($espeStats as $s) {
            $stIns->execute([':mid' => $matchId, ':tt' => 'espe', ':n' => (int)($s['num'] ?? 0), ':nom' => $s['nom'] ?? '', ':min' => $s['min'] ?? '00:00', ':pts' => (int)($s['pts'] ?? 0), ':tirs' => (int)($s['tirs'] ?? 0), ':t3' => (int)($s['t3'] ?? 0), ':t2i' => (int)($s['t2i'] ?? 0), ':t2e' => (int)($s['t2e'] ?? 0), ':lf' => (int)($s['lf'] ?? 0), ':f' => (int)($s['fautes'] ?? 0)]);
        }
        // Insérer stats adversaire
        foreach ($advStats as $s) {
            $stIns->execute([':mid' => $matchId, ':tt' => 'adv', ':n' => (int)($s['num'] ?? 0), ':nom' => $s['nom'] ?? '', ':min' => $s['min'] ?? '00:00', ':pts' => (int)($s['pts'] ?? 0), ':tirs' => (int)($s['tirs'] ?? 0), ':t3' => (int)($s['t3'] ?? 0), ':t2i' => (int)($s['t2i'] ?? 0), ':t2e' => (int)($s['t2e'] ?? 0), ':lf' => (int)($s['lf'] ?? 0), ':f' => (int)($s['fautes'] ?? 0)]);
        }
        echo json_encode(['success' => true, 'match_id' => $matchId]);

        // ═══ Email notification aux parents ═══
        $advNom = ($eqA['short'] ?? '') === 'ESPE' ? ($eqB['nom'] ?? 'Adversaire') : ($eqA['nom'] ?? 'Adversaire');
        $dateFormatted = date('d/m/Y', strtotime($date));
        $hasStats = !empty($espeStats);

        if ($isNewMatch) {
            $subj = "Nouveau match — J$journee vs $advNom";
            $html = "<p>📅 <strong>J$journee — $dateFormatted</strong>" . ($heure ? " à $heure" : "") . "</p>"
                  . "<p>🆚 ESPE vs <strong>$advNom</strong></p>"
                  . ($lieu ? "<p>📍 $lieu ($domExt)</p>" : "")
                  . "<p style='margin-top:16px'><a href='https://espeu9.fr/#matchs' style='display:inline-block;background:#1a6b2e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold'>Voir le match →</a></p>";
        } elseif ($hasStats) {
            $resultat = $espeScore > $advScore ? "Victoire 🎉" : ($espeScore < $advScore ? "Défaite" : "Égalité");
            $subj = "Stats — J$journee vs $advNom ($espeScore-$advScore)";
            $html = "<p>📊 <strong>Les stats du match sont disponibles !</strong></p>"
                  . "<p>🆚 ESPE <strong>$espeScore - $advScore</strong> $advNom → $resultat</p>"
                  . "<p style='margin-top:16px'><a href='https://espeu9.fr/#matchs' style='display:inline-block;background:#1a6b2e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold'>Voir les stats →</a></p>";
        } else {
            $subj = "Match modifié — J$journee vs $advNom";
            $html = "<p>✏️ <strong>Le match J$journee a été mis à jour</strong></p>"
                  . "<p>📅 $dateFormatted" . ($heure ? " à $heure" : "") . "</p>"
                  . "<p>🆚 ESPE <strong>$espeScore - $advScore</strong> $advNom</p>"
                  . "<p style='margin-top:16px'><a href='https://espeu9.fr/#matchs' style='display:inline-block;background:#1a6b2e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold'>Voir le match →</a></p>";
        }
        notifyAllParents($subj, $html);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

case 'delete_match':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'POST requis']); break; }
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') { http_response_code(403); echo json_encode(['error' => 'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error' => 'match_id requis']); break; }
    try {
        $db = getDB();
        // Supprimer les photos associées
        $st = $db->prepare("SELECT filename FROM match_photos WHERE match_id = :mid");
        $st->execute([':mid' => $matchId]);
        while ($ph = $st->fetch()) {
            $f = __DIR__ . '/uploads/' . $ph['filename'];
            if (file_exists($f)) unlink($f);
        }
        $db->prepare("DELETE FROM match_photos WHERE match_id = :mid")->execute([':mid' => $matchId]);
        // Supprimer les notes coach du match
        $db->prepare("DELETE FROM coach_notes WHERE type = 'match' AND ref_id = :mid")->execute([':mid' => $matchId]);
        // Supprimer les extras
        $db->prepare("DELETE FROM match_extras WHERE match_id = :mid")->execute([':mid' => $matchId]);
        // Supprimer le match (CASCADE supprime aussi les stats dans match_player_stats)
        $st2 = $db->prepare("DELETE FROM match_results WHERE id = :mid");
        $st2->execute([':mid' => $matchId]);
        echo json_encode(['success' => true, 'deleted' => $st2->rowCount()]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

// ═══ EXTRACTION STATS DEPUIS FEUILLE DE MATCH (pour match existant) ═══
case 'extract_match_stats':
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'POST requis']); break; }
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') { http_response_code(403); echo json_encode(['error' => 'Coach requis']); break; }
    // Rate limit: même pool que analyze_match_sheet
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'ai_scan', 10, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop de scans IA. Réessaye dans 1 heure.']); break;
    }
    recordAttempt($clientIp, 'ai_scan');
    if (!defined('CLAUDE_API_KEY') || !CLAUDE_API_KEY) { http_response_code(500); echo json_encode(['error' => 'Clé API Claude non configurée']); break; }
    if (!isset($_FILES['sheet']) || $_FILES['sheet']['error'] !== UPLOAD_ERR_OK) { http_response_code(400); echo json_encode(['error' => 'Fichier image/PDF requis']); break; }
    $matchId = (int)($_POST['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error' => 'match_id requis']); break; }

    $file = $_FILES['sheet'];
    if ($file['size'] > 15 * 1024 * 1024) { http_response_code(400); echo json_encode(['error' => 'Max 15 Mo']); break; }

    $pdfData = file_get_contents($file['tmp_name']);
    $base64 = base64_encode($pdfData);
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $isImage = in_array($mime, ['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
    $isPdf = ($mime === 'application/pdf');
    if (!$isImage && !$isPdf) { http_response_code(400); echo json_encode(['error' => 'Format non supporté. Envoie un PDF ou une image (JPG, PNG).']); break; }

    $docContent = $isImage ? [
        'type' => 'image',
        'source' => ['type' => 'base64', 'media_type' => $mime, 'data' => $base64]
    ] : [
        'type' => 'document',
        'source' => ['type' => 'base64', 'media_type' => 'application/pdf', 'data' => $base64]
    ];

    $statsPrompt = <<<'PROMPT'
Analyse cette feuille de match de basketball (catégorie U9/U11 en France — FFBB).

Extrais UNIQUEMENT les statistiques des joueurs des DEUX équipes.
Renvoie UNIQUEMENT un objet JSON valide (sans markdown, sans backticks, sans texte avant/après).

Format JSON attendu :
{
  "espeStats": [
    {"num": 6, "nom": "NOM Prénom", "min": "15:06", "pts": 2, "tirs": 1, "t3": 0, "t2i": 1, "t2e": 0, "lf": 0, "fautes": 0}
  ],
  "advStats": [
    {"num": 4, "nom": "NOM Prénom", "min": "09:20", "pts": 0, "tirs": 0, "t3": 0, "t2i": 0, "t2e": 0, "lf": 0, "fautes": 0}
  ]
}

RÈGLES IMPORTANTES :
- L'équipe ESPE (ou "ESPE Basket Châlons", "EBCCA", "Châlons") va dans espeStats, l'autre équipe dans advStats
- "tirs" = nombre total de tirs réussis (paniers marqués)
- "t2i" = tirs à 2 points réussis dans la raquette
- "t2e" = tirs à 2 points réussis hors raquette
- "t3" = tirs à 3 points réussis
- "lf" = lancers francs réussis
- "fautes" = nombre de fautes personnelles
- "min" = temps de jeu au format "MM:SS"
- Si une donnée est illisible ou absente, mets 0 ou "00:00"
- Les noms doivent être en format "NOM Prénom" (majuscules pour le nom de famille)
- Renvoie UNIQUEMENT le JSON, rien d'autre
PROMPT;

    $payload = json_encode([
        'model' => 'claude-sonnet-4-20250514',
        'max_tokens' => 4000,
        'messages' => [
            ['role' => 'user', 'content' => [$docContent, ['type' => 'text', 'text' => $statsPrompt]]]
        ]
    ]);

    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'x-api-key: ' . CLAUDE_API_KEY,
            'anthropic-version: 2023-06-01'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 120,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) { http_response_code(500); echo json_encode(['error' => 'Erreur réseau: ' . $curlError]); break; }
    if ($httpCode !== 200) {
        $errData = json_decode($response, true);
        $errMsg = $errData['error']['message'] ?? 'Erreur API Claude (HTTP ' . $httpCode . ')';
        http_response_code(500); echo json_encode(['error' => $errMsg]); break;
    }

    $result = json_decode($response, true);
    $textContent = '';
    foreach (($result['content'] ?? []) as $block) {
        if (($block['type'] ?? '') === 'text') $textContent .= $block['text'];
    }
    $textContent = trim(preg_replace('/^```json\s*/i', '', trim($textContent)));
    $textContent = trim(preg_replace('/\s*```$/i', '', $textContent));

    $statsData = json_decode($textContent, true);
    if (!$statsData || (!isset($statsData['espeStats']) && !isset($statsData['advStats']))) {
        http_response_code(500); echo json_encode(['error' => 'Impossible de parser les stats', 'raw' => substr($textContent, 0, 500)]); break;
    }

    // Sauvegarder les stats dans la base pour ce match
    try {
        $db = getDB();
        // Vérifier que le match existe
        $st = $db->prepare("SELECT id FROM match_results WHERE id = :mid"); $st->execute([':mid' => $matchId]);
        if (!$st->fetch()) { http_response_code(404); echo json_encode(['error' => 'Match introuvable']); break; }

        // Supprimer les anciennes stats
        $db->prepare("DELETE FROM match_player_stats WHERE match_id = :mid")->execute([':mid' => $matchId]);

        // Insérer les nouvelles stats
        $stIns = $db->prepare("INSERT INTO match_player_stats (match_id, team_type, num, nom, minutes, pts, tirs, t3, t2i, t2e, lf, fautes) VALUES (:mid, :tt, :n, :nom, :min, :pts, :tirs, :t3, :t2i, :t2e, :lf, :f)");
        foreach (($statsData['espeStats'] ?? []) as $s) {
            $stIns->execute([':mid' => $matchId, ':tt' => 'espe', ':n' => (int)($s['num'] ?? 0), ':nom' => $s['nom'] ?? '', ':min' => $s['min'] ?? '00:00', ':pts' => (int)($s['pts'] ?? 0), ':tirs' => (int)($s['tirs'] ?? 0), ':t3' => (int)($s['t3'] ?? 0), ':t2i' => (int)($s['t2i'] ?? 0), ':t2e' => (int)($s['t2e'] ?? 0), ':lf' => (int)($s['lf'] ?? 0), ':f' => (int)($s['fautes'] ?? 0)]);
        }
        foreach (($statsData['advStats'] ?? []) as $s) {
            $stIns->execute([':mid' => $matchId, ':tt' => 'adv', ':n' => (int)($s['num'] ?? 0), ':nom' => $s['nom'] ?? '', ':min' => $s['min'] ?? '00:00', ':pts' => (int)($s['pts'] ?? 0), ':tirs' => (int)($s['tirs'] ?? 0), ':t3' => (int)($s['t3'] ?? 0), ':t2i' => (int)($s['t2i'] ?? 0), ':t2e' => (int)($s['t2e'] ?? 0), ':lf' => (int)($s['lf'] ?? 0), ':f' => (int)($s['fautes'] ?? 0)]);
        }

        echo json_encode([
            'success' => true,
            'espeStats' => $statsData['espeStats'] ?? [],
            'advStats' => $statsData['advStats'] ?? [],
            'message' => 'Stats extraites et sauvegardées'
        ]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

// ═══ GALERIE MÉDIAS ═══

case 'get_media':
    if (!$uid) { http_response_code(401); echo json_encode(['error' => 'Non connecté']); break; }
    $matchFilter = isset($_GET['match_id']) ? (int)$_GET['match_id'] : null;
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS media (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            username VARCHAR(100) NOT NULL DEFAULT '',
            match_id INT DEFAULT NULL,
            filename VARCHAR(255) NOT NULL,
            original_name VARCHAR(255) NOT NULL,
            mime_type VARCHAR(100) NOT NULL,
            file_size INT NOT NULL DEFAULT 0,
            media_type ENUM('photo','video') NOT NULL DEFAULT 'photo',
            caption VARCHAR(500) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_match (match_id),
            INDEX idx_created (created_at DESC)
        )");
        if ($matchFilter) {
            $st = $db->prepare("SELECT id, user_id, username, match_id, filename, original_name, mime_type, file_size, media_type, caption, created_at FROM media WHERE match_id = :mid ORDER BY created_at DESC");
            $st->execute([':mid' => $matchFilter]);
        } else {
            $st = $db->query("SELECT id, user_id, username, match_id, filename, original_name, mime_type, file_size, media_type, caption, created_at FROM media ORDER BY created_at DESC LIMIT 200");
        }
        $media = [];
        while ($r = $st->fetch()) {
            $media[] = [
                'id' => (int)$r['id'],
                'user_id' => (int)$r['user_id'],
                'username' => $r['username'],
                'match_id' => $r['match_id'] ? (int)$r['match_id'] : null,
                'url' => 'uploads/media/' . $r['filename'],
                'original_name' => $r['original_name'],
                'mime_type' => $r['mime_type'],
                'file_size' => (int)$r['file_size'],
                'media_type' => $r['media_type'],
                'caption' => $r['caption'],
                'created_at' => $r['created_at']
            ];
        }
        echo json_encode(['success' => true, 'media' => $media]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

case 'upload_media':
    if (!$uid) { http_response_code(401); echo json_encode(['error' => 'Non connecté']); break; }
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'upload_media', 30, 3600)) {
        http_response_code(429); echo json_encode(['error' => 'Trop d\'uploads. Réessayez plus tard.']); break;
    }
    recordAttempt($clientIp, 'upload_media');
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        $code = isset($_FILES['file']) ? $_FILES['file']['error'] : -1;
        if ($code === UPLOAD_ERR_INI_SIZE || $code === UPLOAD_ERR_FORM_SIZE) {
            http_response_code(413); echo json_encode(['error' => 'Fichier trop volumineux (max 100 Mo)']); break;
        }
        http_response_code(400); echo json_encode(['error' => 'Aucun fichier reçu']); break;
    }
    $file = $_FILES['file'];
    $matchId = isset($_POST['match_id']) && $_POST['match_id'] ? (int)$_POST['match_id'] : null;
    $caption = isset($_POST['caption']) ? mb_substr(trim($_POST['caption']), 0, 500) : '';
    // Validation MIME réelle
    $finfo = finfo_open(FILEINFO_MIME_TYPE); $mime = finfo_file($finfo, $file['tmp_name']); finfo_close($finfo);
    $allowedPhotos = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    $allowedVideos = ['video/mp4', 'video/quicktime', 'video/webm', 'video/x-msvideo', 'video/x-matroska'];
    $allowed = array_merge($allowedPhotos, $allowedVideos);
    if (!in_array($mime, $allowed)) {
        http_response_code(400); echo json_encode(['error' => 'Type non autorisé (JPG, PNG, WebP, GIF, MP4, MOV, WebM, AVI, MKV uniquement)']); break;
    }
    $mediaType = in_array($mime, $allowedPhotos) ? 'photo' : 'video';
    // Limite taille : 100 Mo
    if ($file['size'] > 100 * 1024 * 1024) {
        http_response_code(413); echo json_encode(['error' => 'Fichier trop volumineux (max 100 Mo)']); break;
    }
    // Répertoire
    $dir = __DIR__ . '/uploads/media/';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $safeExts = ['jpg','jpeg','png','webp','gif','mp4','mov','webm','avi','mkv'];
    if (!in_array($ext, $safeExts)) $ext = ($mediaType === 'photo') ? 'jpg' : 'mp4';
    $fn = 'media_' . time() . '_' . bin2hex(random_bytes(8)) . '.' . $ext;
    if (!move_uploaded_file($file['tmp_name'], $dir . $fn)) {
        http_response_code(500); echo json_encode(['error' => 'Erreur upload']); break;
    }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS media (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            username VARCHAR(100) NOT NULL DEFAULT '',
            match_id INT DEFAULT NULL,
            filename VARCHAR(255) NOT NULL,
            original_name VARCHAR(255) NOT NULL,
            mime_type VARCHAR(100) NOT NULL,
            file_size INT NOT NULL DEFAULT 0,
            media_type ENUM('photo','video') NOT NULL DEFAULT 'photo',
            caption VARCHAR(500) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_match (match_id),
            INDEX idx_created (created_at DESC)
        )");
        // Récupérer le nom d'utilisateur
        $stU = $db->prepare("SELECT display_name, username FROM users WHERE id = :id");
        $stU->execute([':id' => $uid]);
        $uRow = $stU->fetch();
        $displayName = $uRow ? ($uRow['display_name'] ?: $uRow['username']) : 'Inconnu';
        $st = $db->prepare("INSERT INTO media (user_id, username, match_id, filename, original_name, mime_type, file_size, media_type, caption) VALUES (:uid, :uname, :mid, :fn, :orig, :mime, :sz, :mt, :cap)");
        $st->execute([':uid' => $uid, ':uname' => $displayName, ':mid' => $matchId, ':fn' => $fn, ':orig' => $file['name'], ':mime' => $mime, ':sz' => $file['size'], ':mt' => $mediaType, ':cap' => $caption]);
        $newId = (int)$db->lastInsertId();
        echo json_encode(['success' => true, 'media' => [
            'id' => $newId, 'url' => 'uploads/media/' . $fn, 'original_name' => $file['name'],
            'mime_type' => $mime, 'file_size' => $file['size'], 'media_type' => $mediaType,
            'username' => $displayName, 'match_id' => $matchId, 'caption' => $caption
        ]]);
    } catch (Exception $e) {
        @unlink($dir . $fn);
        http_response_code(500); echo json_encode(['error' => 'Erreur serveur']);
    }
    break;

case 'delete_media':
    if (!$uid) { http_response_code(401); echo json_encode(['error' => 'Non connecté']); break; }
    $input = json_decode(file_get_contents('php://input'), true);
    $mediaId = (int)($input['media_id'] ?? 0);
    if (!$mediaId) { http_response_code(400); echo json_encode(['error' => 'media_id requis']); break; }
    try {
        $db = getDB();
        $st = $db->prepare("SELECT id, user_id, filename FROM media WHERE id = :id");
        $st->execute([':id' => $mediaId]);
        $m = $st->fetch();
        if (!$m) { http_response_code(404); echo json_encode(['error' => 'Média introuvable']); break; }
        // Seul l'auteur ou le coach peut supprimer
        if ((int)$m['user_id'] !== $uid && $role !== 'coach') {
            http_response_code(403); echo json_encode(['error' => 'Non autorisé']); break;
        }
        $f = __DIR__ . '/uploads/media/' . $m['filename'];
        if (file_exists($f)) unlink($f);
        $db->prepare("DELETE FROM media WHERE id = :id")->execute([':id' => $mediaId]);
        echo json_encode(['success' => true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error' => 'Erreur serveur']); }
    break;

// ═══ ACTUALITÉS (Coach only) ═══

case 'get_news':
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS news (
            id INT AUTO_INCREMENT PRIMARY KEY,
            content TEXT NOT NULL,
            image VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        try { $db->exec("ALTER TABLE news ADD COLUMN image VARCHAR(255) DEFAULT NULL AFTER content"); } catch(Exception $e2) {}
        $st = $db->query("SELECT id, content, image, created_at, updated_at FROM news ORDER BY created_at DESC LIMIT 20");
        $news = [];
        while ($r = $st->fetch()) { $news[] = ['id'=>(int)$r['id'], 'content'=>$r['content'], 'image'=>$r['image'] ? 'uploads/news/'.$r['image'] : null, 'created_at'=>$r['created_at'], 'updated_at'=>$r['updated_at']]; }
        echo json_encode(['success'=>true, 'news'=>$news]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'post_news':
    if ($role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Réservé au coach']); break; }
    $content = trim($_POST['content'] ?? '');
    if (!$content || mb_strlen($content) > 2000) { http_response_code(400); echo json_encode(['error'=>'Contenu requis (max 2000 car.)']); break; }
    $imageFn = null;
    if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
        $imgFile = $_FILES['image'];
        $finfo = finfo_open(FILEINFO_MIME_TYPE); $mime = finfo_file($finfo, $imgFile['tmp_name']); finfo_close($finfo);
        if (!in_array($mime, ['image/jpeg','image/png','image/webp','image/gif'])) {
            http_response_code(400); echo json_encode(['error'=>'Image JPG, PNG, WebP ou GIF uniquement']); break;
        }
        if ($imgFile['size'] > 10 * 1024 * 1024) { http_response_code(413); echo json_encode(['error'=>'Image trop volumineuse (max 10 Mo)']); break; }
        $dir = __DIR__ . '/uploads/news/';
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        $ext = strtolower(pathinfo($imgFile['name'], PATHINFO_EXTENSION));
        if (!in_array($ext, ['jpg','jpeg','png','webp','gif'])) $ext = 'jpg';
        $imageFn = 'news_' . time() . '_' . bin2hex(random_bytes(6)) . '.' . $ext;
        if (!move_uploaded_file($imgFile['tmp_name'], $dir . $imageFn)) { http_response_code(500); echo json_encode(['error'=>'Erreur upload image']); break; }
    }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS news (
            id INT AUTO_INCREMENT PRIMARY KEY,
            content TEXT NOT NULL,
            image VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )");
        try { $db->exec("ALTER TABLE news ADD COLUMN image VARCHAR(255) DEFAULT NULL AFTER content"); } catch(Exception $e2) {}
        $st = $db->prepare("INSERT INTO news (content, image) VALUES (:c, :img)");
        $st->execute([':c'=>$content, ':img'=>$imageFn]);
        $newId = (int)$db->lastInsertId();

        // ═══ Envoyer un email à tous les parents ═══
        try {
            $stUsers = $db->query("SELECT email, display_name FROM users WHERE role='parent' AND email IS NOT NULL AND email != ''");
            $parents = $stUsers->fetchAll(PDO::FETCH_ASSOC);
            $preview = mb_substr($content, 0, 300);
            $htmlBody = "<p style='font-size:15px;line-height:1.6'>" . nl2br(htmlspecialchars($preview, ENT_QUOTES, 'UTF-8'));
            if (mb_strlen($content) > 300) $htmlBody .= "...</p><p><em>Message tronqué — ouvre le site pour lire la suite.</em></p>";
            else $htmlBody .= "</p>";
            if ($imageFn) {
                $htmlBody .= "<p><img src='https://espeu9.fr/uploads/news/$imageFn' alt='Image' style='max-width:100%;border-radius:8px;margin-top:10px'></p>";
            }
            $htmlBody .= "<p style='margin-top:16px'><a href='https://espeu9.fr/#accueil' style='display:inline-block;background:#1a6b2e;color:#fff;padding:10px 20px;border-radius:6px;text-decoration:none;font-weight:bold'>Voir sur le site →</a></p>";
            foreach ($parents as $p) {
                if ($p['email']) {
                    sendEmailNotif($p['email'], 'Nouvelle actualité', $htmlBody);
                }
            }
        } catch (Exception $emailErr) { /* L'email en erreur n'empêche pas la publication */ }

        echo json_encode(['success'=>true, 'news'=>['id'=>$newId, 'content'=>$content, 'image'=>$imageFn ? 'uploads/news/'.$imageFn : null, 'created_at'=>date('Y-m-d H:i:s')]]);
    } catch (Exception $e) {
        if ($imageFn) @unlink(__DIR__.'/uploads/news/'.$imageFn);
        http_response_code(500); echo json_encode(['error'=>'Erreur serveur']);
    }
    break;

case 'update_news':
    if ($role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Réservé au coach']); break; }
    $input = json_decode(file_get_contents('php://input'), true);
    $newsId = (int)($input['id'] ?? 0);
    $content = trim($input['content'] ?? '');
    if (!$newsId || !$content || mb_strlen($content) > 2000) { http_response_code(400); echo json_encode(['error'=>'Données invalides']); break; }
    try {
        $db = getDB();
        $db->prepare("UPDATE news SET content = :c WHERE id = :id")->execute([':c'=>$content, ':id'=>$newsId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'delete_news':
    if ($role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Réservé au coach']); break; }
    $input = json_decode(file_get_contents('php://input'), true);
    $newsId = (int)($input['id'] ?? 0);
    if (!$newsId) { http_response_code(400); echo json_encode(['error'=>'id requis']); break; }
    try {
        $db = getDB();
        $st = $db->prepare("SELECT image FROM news WHERE id = :id"); $st->execute([':id'=>$newsId]); $row = $st->fetch();
        if ($row && $row['image']) { $f = __DIR__.'/uploads/news/'.$row['image']; if (file_exists($f)) unlink($f); }
        $db->prepare("DELETE FROM news WHERE id = :id")->execute([':id'=>$newsId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

// ═══ CHAT MÉDIAS ═══

case 'get_media_chat':
    if (!$uid) { http_response_code(401); echo json_encode(['error' => 'Non connecté']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS media_chat (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            display_name VARCHAR(100) NOT NULL DEFAULT '',
            role VARCHAR(20) NOT NULL DEFAULT 'parent',
            player_id INT DEFAULT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        $st = $db->query("SELECT id, user_id, display_name, role, player_id, message, created_at FROM media_chat ORDER BY created_at DESC LIMIT 100");
        $msgs = [];
        while ($r = $st->fetch()) { $msgs[] = ['id'=>(int)$r['id'], 'user_id'=>(int)$r['user_id'], 'display_name'=>$r['display_name'], 'role'=>$r['role'], 'player_id'=>$r['player_id']?(int)$r['player_id']:null, 'message'=>$r['message'], 'created_at'=>$r['created_at']]; }
        echo json_encode(['success'=>true, 'messages'=>array_reverse($msgs)]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'post_media_chat':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'media_chat', 30, 3600)) {
        http_response_code(429); echo json_encode(['error'=>'Trop de messages. Réessayez plus tard.']); break;
    }
    recordAttempt($clientIp, 'media_chat');
    $input = json_decode(file_get_contents('php://input'), true);
    $message = trim($input['message'] ?? '');
    if (!$message || mb_strlen($message) > 1000) { http_response_code(400); echo json_encode(['error'=>'Message requis (max 1000 car.)']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS media_chat (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            display_name VARCHAR(100) NOT NULL DEFAULT '',
            role VARCHAR(20) NOT NULL DEFAULT 'parent',
            player_id INT DEFAULT NULL,
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        $stU = $db->prepare("SELECT display_name, role, player_id FROM users WHERE id = :id");
        $stU->execute([':id'=>$uid]);
        $u = $stU->fetch();
        $dname = $u ? ($u['display_name'] ?: 'Utilisateur') : 'Utilisateur';
        $urole = $u ? $u['role'] : 'parent';
        $pid = $u ? $u['player_id'] : null;
        $st = $db->prepare("INSERT INTO media_chat (user_id, display_name, role, player_id, message) VALUES (:uid, :dn, :r, :pid, :msg)");
        $st->execute([':uid'=>$uid, ':dn'=>$dname, ':r'=>$urole, ':pid'=>$pid, ':msg'=>$message]);
        $newId = (int)$db->lastInsertId();
        echo json_encode(['success'=>true, 'msg'=>['id'=>$newId, 'user_id'=>$uid, 'display_name'=>$dname, 'role'=>$urole, 'player_id'=>$pid, 'message'=>$message, 'created_at'=>date('Y-m-d H:i:s')]]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'delete_media_chat':
    if ($role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Réservé au coach']); break; }
    $input = json_decode(file_get_contents('php://input'), true);
    $msgId = (int)($input['id'] ?? 0);
    if (!$msgId) { http_response_code(400); echo json_encode(['error'=>'id requis']); break; }
    try {
        $db = getDB();
        $db->prepare("DELETE FROM media_chat WHERE id = :id")->execute([':id'=>$msgId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

// ═══ MATCHS À VENIR (ajoutés manuellement) ═══
case 'get_custom_upcoming':
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS upcoming_matches (
            id INT AUTO_INCREMENT PRIMARY KEY,
            journee VARCHAR(20) NOT NULL DEFAULT '',
            date VARCHAR(20) NOT NULL,
            heure VARCHAR(10) DEFAULT '',
            heure_rdv VARCHAR(10) DEFAULT '',
            lieu VARCHAR(100) DEFAULT '',
            gymnase VARCHAR(150) DEFAULT '',
            dom_ext ENUM('dom','ext') DEFAULT 'dom',
            adversaire VARCHAR(100) NOT NULL,
            logo_url VARCHAR(500) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        // Add columns if missing (upgrade path)
        try { $db->exec("ALTER TABLE upcoming_matches ADD COLUMN heure_rdv VARCHAR(10) DEFAULT '' AFTER heure"); } catch (Exception $e) {}
        try { $db->exec("ALTER TABLE upcoming_matches ADD COLUMN logo_url VARCHAR(500) DEFAULT '' AFTER adversaire"); } catch (Exception $e) {}
        $st = $db->query("SELECT * FROM upcoming_matches ORDER BY STR_TO_DATE(date, '%d/%m/%Y') ASC");
        $matches = [];
        while ($r = $st->fetch(PDO::FETCH_ASSOC)) {
            $matches[] = ['id'=>'custom_'.$r['id'], 'db_id'=>(int)$r['id'], 'journee'=>$r['journee'], 'date'=>$r['date'], 'heure'=>$r['heure'], 'heureRdv'=>$r['heure_rdv']??'', 'lieu'=>$r['lieu'], 'gymnase'=>$r['gymnase'], 'domExt'=>$r['dom_ext'], 'adversaire'=>$r['adversaire'], 'logoUrl'=>$r['logo_url']??'', 'custom'=>true];
        }
        echo json_encode(['success'=>true, 'matches'=>$matches]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'save_upcoming':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $journee = trim($in['journee'] ?? '');
    $date = trim($in['date'] ?? '');
    $heure = trim($in['heure'] ?? '');
    $heureRdv = trim($in['heureRdv'] ?? '');
    $lieu = trim($in['lieu'] ?? '');
    $gymnase = trim($in['gymnase'] ?? '');
    $domExt = ($in['domExt'] ?? 'dom') === 'ext' ? 'ext' : 'dom';
    $adversaire = trim($in['adversaire'] ?? '');
    $logoUrl = trim($in['logoUrl'] ?? '');
    $editId = (int)($in['edit_id'] ?? 0);
    if (!$date || !$adversaire) { http_response_code(400); echo json_encode(['error'=>'Date et adversaire requis']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS upcoming_matches (
            id INT AUTO_INCREMENT PRIMARY KEY, journee VARCHAR(20) NOT NULL DEFAULT '',
            date VARCHAR(20) NOT NULL, heure VARCHAR(10) DEFAULT '', heure_rdv VARCHAR(10) DEFAULT '',
            lieu VARCHAR(100) DEFAULT '', gymnase VARCHAR(150) DEFAULT '',
            dom_ext ENUM('dom','ext') DEFAULT 'dom',
            adversaire VARCHAR(100) NOT NULL, logo_url VARCHAR(500) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        try { $db->exec("ALTER TABLE upcoming_matches ADD COLUMN heure_rdv VARCHAR(10) DEFAULT '' AFTER heure"); } catch (Exception $e) {}
        try { $db->exec("ALTER TABLE upcoming_matches ADD COLUMN logo_url VARCHAR(500) DEFAULT '' AFTER adversaire"); } catch (Exception $e) {}
        if ($editId > 0) {
            $st = $db->prepare("UPDATE upcoming_matches SET journee=:j, date=:d, heure=:h, heure_rdv=:hr, lieu=:l, gymnase=:g, dom_ext=:de, adversaire=:a, logo_url=:logo WHERE id=:id");
            $st->execute([':j'=>$journee, ':d'=>$date, ':h'=>$heure, ':hr'=>$heureRdv, ':l'=>$lieu, ':g'=>$gymnase, ':de'=>$domExt, ':a'=>$adversaire, ':logo'=>$logoUrl, ':id'=>$editId]);
        } else {
            $st = $db->prepare("INSERT INTO upcoming_matches (journee, date, heure, heure_rdv, lieu, gymnase, dom_ext, adversaire, logo_url) VALUES (:j, :d, :h, :hr, :l, :g, :de, :a, :logo)");
            $st->execute([':j'=>$journee, ':d'=>$date, ':h'=>$heure, ':hr'=>$heureRdv, ':l'=>$lieu, ':g'=>$gymnase, ':de'=>$domExt, ':a'=>$adversaire, ':logo'=>$logoUrl]);
            $editId = (int)$db->lastInsertId();
        }
        // Also save to match_extras for compatibility
        $matchKey = 'custom_' . $editId;
        $db->exec("CREATE TABLE IF NOT EXISTS match_extras (match_id VARCHAR(50) PRIMARY KEY, gymnase VARCHAR(150) DEFAULT '', heure_rdv VARCHAR(10) DEFAULT '')");
        $stE = $db->prepare("INSERT INTO match_extras (match_id, gymnase, heure_rdv) VALUES (:mid, :g, :hr) ON DUPLICATE KEY UPDATE gymnase=:g2, heure_rdv=:hr2");
        $stE->execute([':mid'=>$matchKey, ':g'=>$gymnase, ':hr'=>$heureRdv, ':g2'=>$gymnase, ':hr2'=>$heureRdv]);
        // Notify parents
        notifyAllParents(
            "Nouveau match \u2014 " . ($journee ? $journee : "Coupe") . " vs " . $adversaire,
            "<p>\uD83C\uDFC0 Un nouveau match a \u00E9t\u00E9 ajout\u00E9 :</p><p><strong>" . ($journee ? $journee : "Coupe") . " vs " . htmlspecialchars($adversaire) . "</strong><br>" . htmlspecialchars($date) . ($heure ? " \u00E0 " . htmlspecialchars($heure) : "") . ($heureRdv ? " (convocation " . htmlspecialchars($heureRdv) . ")" : "") . "<br>" . htmlspecialchars($lieu) . " (" . ($domExt === "dom" ? "Domicile" : "Ext\u00E9rieur") . ")</p>"
        );
        echo json_encode(['success'=>true, 'id'=>$editId]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'delete_upcoming':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $delId = (int)($in['id'] ?? 0);
    if (!$delId) { http_response_code(400); echo json_encode(['error'=>'id requis']); break; }
    try {
        $db = getDB();
        $db->prepare("DELETE FROM upcoming_matches WHERE id = :id")->execute([':id'=>$delId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

// ═══ CHAT PAR MATCH ═══
case 'get_match_chat':
    $matchId = (int)($_GET['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error'=>'match_id requis']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS match_chat (
            id INT AUTO_INCREMENT PRIMARY KEY,
            match_id INT NOT NULL,
            user_id INT NOT NULL,
            display_name VARCHAR(100) DEFAULT '',
            role VARCHAR(20) DEFAULT 'parent',
            message TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_match (match_id)
        )");
        $st = $db->prepare("SELECT id, user_id, display_name, role, message, created_at FROM match_chat WHERE match_id = :mid ORDER BY created_at ASC LIMIT 200");
        $st->execute([':mid'=>$matchId]);
        $msgs = [];
        // Get player_id for each user
        $userPlayers = [];
        while ($r = $st->fetch()) {
            if (!isset($userPlayers[$r['user_id']])) {
                $stP = $db->prepare("SELECT player_id FROM users WHERE id = :id");
                $stP->execute([':id'=>$r['user_id']]); $up = $stP->fetch();
                $userPlayers[$r['user_id']] = $up ? $up['player_id'] : null;
            }
            $msgs[] = ['id'=>(int)$r['id'], 'user_id'=>(int)$r['user_id'], 'display_name'=>$r['display_name'], 'role'=>$r['role'], 'player_id'=>$userPlayers[$r['user_id']] ? (int)$userPlayers[$r['user_id']] : null, 'message'=>$r['message'], 'created_at'=>$r['created_at']];
        }
        echo json_encode(['success'=>true, 'messages'=>$msgs]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'post_match_chat':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (!checkRateLimit($clientIp, 'match_chat', 40, 3600)) {
        http_response_code(429); echo json_encode(['error'=>'Trop de messages. Réessayez plus tard.']); break;
    }
    recordAttempt($clientIp, 'match_chat');
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    $message = trim($in['message'] ?? '');
    if (!$matchId || !$message || mb_strlen($message) > 1000) { http_response_code(400); echo json_encode(['error'=>'Message requis (max 1000 car.)']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS match_chat (
            id INT AUTO_INCREMENT PRIMARY KEY, match_id INT NOT NULL, user_id INT NOT NULL,
            display_name VARCHAR(100) DEFAULT '', role VARCHAR(20) DEFAULT 'parent',
            message TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_match (match_id)
        )");
        $stU = $db->prepare("SELECT display_name, role, player_id FROM users WHERE id = :id");
        $stU->execute([':id'=>$uid]); $u = $stU->fetch();
        $dname = $u ? ($u['display_name'] ?: 'Utilisateur') : 'Utilisateur';
        $urole = $u ? $u['role'] : 'parent';
        $upid = $u ? $u['player_id'] : null;
        $st = $db->prepare("INSERT INTO match_chat (match_id, user_id, display_name, role, message) VALUES (:mid, :uid, :dn, :r, :msg)");
        $st->execute([':mid'=>$matchId, ':uid'=>$uid, ':dn'=>$dname, ':r'=>$urole, ':msg'=>$message]);
        $newId = (int)$db->lastInsertId();
        echo json_encode(['success'=>true, 'msg'=>['id'=>$newId, 'user_id'=>$uid, 'display_name'=>$dname, 'role'=>$urole, 'player_id'=>$upid?(int)$upid:null, 'message'=>$message, 'created_at'=>date('Y-m-d H:i:s')]]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'delete_match_chat':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $msgId = (int)($in['id'] ?? 0);
    if (!$msgId) { http_response_code(400); echo json_encode(['error'=>'id requis']); break; }
    try {
        $db = getDB();
        // Coach can delete any, parent can delete their own
        if ($role === 'coach') {
            $db->prepare("DELETE FROM match_chat WHERE id = :id")->execute([':id'=>$msgId]);
        } else {
            $db->prepare("DELETE FROM match_chat WHERE id = :id AND user_id = :uid")->execute([':id'=>$msgId, ':uid'=>$uid]);
        }
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

// ═══ COVOITURAGE ═══
case 'get_covoiturage':
    $matchId = (int)($_GET['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error'=>'match_id requis']); break; }
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS covoiturage (
            id INT AUTO_INCREMENT PRIMARY KEY,
            match_id INT NOT NULL,
            user_id INT NOT NULL,
            type ENUM('driver','passenger') NOT NULL DEFAULT 'driver',
            seats_total INT DEFAULT 3,
            driver_id INT DEFAULT NULL,
            message VARCHAR(255) DEFAULT '',
            display_name VARCHAR(100) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_match (match_id, user_id)
        )");
        $st = $db->prepare("SELECT c.*, u.display_name as uname FROM covoiturage c LEFT JOIN users u ON c.user_id = u.id WHERE c.match_id = :mid ORDER BY c.type ASC, c.created_at ASC");
        $st->execute([':mid'=>$matchId]);
        $rows = $st->fetchAll(PDO::FETCH_ASSOC);
        $drivers = []; $passengers = [];
        foreach ($rows as $r) {
            $item = ['id'=>(int)$r['id'], 'user_id'=>(int)$r['user_id'], 'display_name'=>$r['uname']?:$r['display_name'], 'message'=>$r['message'], 'created_at'=>$r['created_at']];
            if ($r['type'] === 'driver') {
                $item['seats_total'] = (int)$r['seats_total'];
                $item['passengers'] = [];
                $drivers[$r['id']] = $item;
            } else {
                $item['driver_id'] = $r['driver_id'] ? (int)$r['driver_id'] : null;
                $passengers[] = $item;
            }
        }
        // Attach passengers to drivers
        foreach ($passengers as $p) {
            if ($p['driver_id'] && isset($drivers[$p['driver_id']])) {
                $drivers[$p['driver_id']]['passengers'][] = $p;
            }
        }
        echo json_encode(['success'=>true, 'drivers'=>array_values($drivers), 'unmatched'=>array_values(array_filter($passengers, fn($p) => !$p['driver_id'] || !isset($drivers[$p['driver_id']])))]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'save_covoiturage':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    $type = $in['type'] ?? 'driver'; // 'driver' or 'passenger'
    $seatsTotal = max(1, min(8, (int)($in['seats_total'] ?? 3)));
    $message = trim(mb_substr($in['message'] ?? '', 0, 255));
    $driverCovoitId = (int)($in['driver_id'] ?? 0); // for passengers: which driver entry
    if (!$matchId) { http_response_code(400); echo json_encode(['error'=>'match_id requis']); break; }
    if (!in_array($type, ['driver','passenger'])) $type = 'driver';
    try {
        $db = getDB();
        $db->exec("CREATE TABLE IF NOT EXISTS covoiturage (
            id INT AUTO_INCREMENT PRIMARY KEY, match_id INT NOT NULL, user_id INT NOT NULL,
            type ENUM('driver','passenger') NOT NULL DEFAULT 'driver',
            seats_total INT DEFAULT 3, driver_id INT DEFAULT NULL,
            message VARCHAR(255) DEFAULT '', display_name VARCHAR(100) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_user_match (match_id, user_id)
        )");
        // Get display name
        $stN = $db->prepare("SELECT display_name FROM users WHERE id = :id");
        $stN->execute([':id'=>$uid]); $urow = $stN->fetch();
        $dname = $urow ? $urow['display_name'] : '';

        if ($type === 'driver') {
            $st = $db->prepare("INSERT INTO covoiturage (match_id, user_id, type, seats_total, message, display_name) VALUES (:mid, :uid, 'driver', :s, :msg, :dn) ON DUPLICATE KEY UPDATE type='driver', seats_total=:s2, message=:msg2, driver_id=NULL");
            $st->execute([':mid'=>$matchId, ':uid'=>$uid, ':s'=>$seatsTotal, ':msg'=>$message, ':dn'=>$dname, ':s2'=>$seatsTotal, ':msg2'=>$message]);
        } else {
            $st = $db->prepare("INSERT INTO covoiturage (match_id, user_id, type, driver_id, message, display_name) VALUES (:mid, :uid, 'passenger', :did, :msg, :dn) ON DUPLICATE KEY UPDATE type='passenger', driver_id=:did2, message=:msg2, seats_total=0");
            $st->execute([':mid'=>$matchId, ':uid'=>$uid, ':did'=>$driverCovoitId?:null, ':msg'=>$message, ':dn'=>$dname, ':did2'=>$driverCovoitId?:null, ':msg2'=>$message]);
        }
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'join_covoiturage':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    $driverCovoitId = (int)($in['driver_covoit_id'] ?? 0);
    if (!$matchId || !$driverCovoitId) { http_response_code(400); echo json_encode(['error'=>'Données manquantes']); break; }
    try {
        $db = getDB();
        // Check seats available
        $stD = $db->prepare("SELECT seats_total FROM covoiturage WHERE id = :did AND type='driver'");
        $stD->execute([':did'=>$driverCovoitId]); $driver = $stD->fetch();
        if (!$driver) { http_response_code(404); echo json_encode(['error'=>'Conducteur non trouvé']); break; }
        $stP = $db->prepare("SELECT COUNT(*) as c FROM covoiturage WHERE driver_id = :did AND type='passenger'");
        $stP->execute([':did'=>$driverCovoitId]); $count = (int)$stP->fetch()['c'];
        if ($count >= $driver['seats_total']) { http_response_code(400); echo json_encode(['error'=>'Plus de place disponible']); break; }
        // Get display name
        $stN = $db->prepare("SELECT display_name FROM users WHERE id = :id");
        $stN->execute([':id'=>$uid]); $urow = $stN->fetch();
        $dname = $urow ? $urow['display_name'] : '';
        // Upsert
        $st = $db->prepare("INSERT INTO covoiturage (match_id, user_id, type, driver_id, display_name) VALUES (:mid, :uid, 'passenger', :did, :dn) ON DUPLICATE KEY UPDATE type='passenger', driver_id=:did2, seats_total=0");
        $st->execute([':mid'=>$matchId, ':uid'=>$uid, ':did'=>$driverCovoitId, ':dn'=>$dname, ':did2'=>$driverCovoitId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'accept_passenger':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    $passengerId = (int)($in['passenger_covoit_id'] ?? 0);
    if (!$matchId || !$passengerId) { http_response_code(400); echo json_encode(['error'=>'Données manquantes']); break; }
    try {
        $db = getDB();
        // Verify the current user is a driver for this match
        $stD = $db->prepare("SELECT id, seats_total FROM covoiturage WHERE match_id = :mid AND user_id = :uid AND type='driver'");
        $stD->execute([':mid'=>$matchId, ':uid'=>$uid]); $driver = $stD->fetch();
        if (!$driver) { http_response_code(403); echo json_encode(['error'=>'Vous n\'êtes pas conducteur pour ce match']); break; }
        // Check seats available
        $stP = $db->prepare("SELECT COUNT(*) as c FROM covoiturage WHERE driver_id = :did AND type='passenger'");
        $stP->execute([':did'=>$driver['id']]); $count = (int)$stP->fetch()['c'];
        if ($count >= $driver['seats_total']) { http_response_code(400); echo json_encode(['error'=>'Plus de place disponible']); break; }
        // Verify passenger exists and is unmatched
        $stV = $db->prepare("SELECT id FROM covoiturage WHERE id = :pid AND type='passenger' AND (driver_id IS NULL OR driver_id = 0)");
        $stV->execute([':pid'=>$passengerId]); 
        if (!$stV->fetch()) { http_response_code(400); echo json_encode(['error'=>'Demande déjà prise en charge']); break; }
        // Link passenger to driver
        $db->prepare("UPDATE covoiturage SET driver_id = :did WHERE id = :pid")->execute([':did'=>$driver['id'], ':pid'=>$passengerId]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

case 'delete_covoiturage':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $matchId = (int)($in['match_id'] ?? 0);
    if (!$matchId) { http_response_code(400); echo json_encode(['error'=>'match_id requis']); break; }
    try {
        $db = getDB();
        // If user was a driver, also unlink passengers
        $stC = $db->prepare("SELECT id, type FROM covoiturage WHERE match_id = :mid AND user_id = :uid");
        $stC->execute([':mid'=>$matchId, ':uid'=>$uid]); $entry = $stC->fetch();
        if ($entry && $entry['type'] === 'driver') {
            $db->prepare("UPDATE covoiturage SET driver_id = NULL WHERE driver_id = :did")->execute([':did'=>$entry['id']]);
        }
        $db->prepare("DELETE FROM covoiturage WHERE match_id = :mid AND user_id = :uid")->execute([':mid'=>$matchId, ':uid'=>$uid]);
        echo json_encode(['success'=>true]);
    } catch (Exception $e) { http_response_code(500); echo json_encode(['error'=>'Erreur serveur']); }
    break;

// ══════════════════════════════════════
// COFFRE-FORT NUMÉRIQUE
// ══════════════════════════════════════

case 'vault_status':
    if (!$uid) { http_response_code(401); echo json_encode(['error'=>'Non connecté']); break; }
    if ($role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Réservé au coach']); break; }
    $db = getDB();
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS vault_passwords (
            user_id INT PRIMARY KEY,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        $db->exec("CREATE TABLE IF NOT EXISTS vault_files (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            filename VARCHAR(255) NOT NULL,
            original_name VARCHAR(500) NOT NULL,
            file_size BIGINT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_vault_user (user_id)
        )");
    } catch (Throwable $e) {}
    $st = $db->prepare("SELECT user_id FROM vault_passwords WHERE user_id=:uid");
    $st->execute([':uid'=>$uid]);
    $hasPassword = (bool)$st->fetch();
    $st2 = $db->prepare("SELECT COALESCE(SUM(file_size),0) as total FROM vault_files WHERE user_id=:uid");
    $st2->execute([':uid'=>$uid]);
    $used = (int)$st2->fetch()['total'];
    echo json_encode(['success'=>true,'has_password'=>$hasPassword,'storage_used'=>$used]);
    break;

case 'vault_setup':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $vpwd = $in['password'] ?? '';
    if (strlen($vpwd) < 6) { http_response_code(400); echo json_encode(['error'=>'Mot de passe trop court (min 6)']); break; }
    $hash = password_hash($vpwd, PASSWORD_DEFAULT);
    $db = getDB();
    $db->prepare("REPLACE INTO vault_passwords (user_id, password_hash) VALUES (:uid,:h)")
       ->execute([':uid'=>$uid,':h'=>$hash]);
    echo json_encode(['success'=>true]);
    break;

case 'vault_unlock':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $db = getDB();
    $st = $db->prepare("SELECT password_hash FROM vault_passwords WHERE user_id=:uid");
    $st->execute([':uid'=>$uid]);
    $row = $st->fetch();
    if (!$row || !password_verify($in['password'] ?? '', $row['password_hash'])) {
        http_response_code(401); echo json_encode(['error'=>'Mot de passe incorrect']); break;
    }
    $st2 = $db->prepare("SELECT id, original_name, file_size, created_at FROM vault_files WHERE user_id=:uid ORDER BY created_at DESC");
    $st2->execute([':uid'=>$uid]);
    echo json_encode(['success'=>true,'files'=>$st2->fetchAll(PDO::FETCH_ASSOC)]);
    break;

case 'vault_upload':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $vpwd = $_POST['vault_pwd'] ?? '';
    $db = getDB();
    $st = $db->prepare("SELECT password_hash FROM vault_passwords WHERE user_id=:uid");
    $st->execute([':uid'=>$uid]);
    $row = $st->fetch();
    if (!$row || !password_verify($vpwd, $row['password_hash'])) {
        http_response_code(401); echo json_encode(['error'=>'Mot de passe coffre incorrect']); break;
    }
    if (empty($_FILES['file'])) { http_response_code(400); echo json_encode(['error'=>'Aucun fichier']); break; }
    $f = $_FILES['file'];
    if ($f['size'] > 15 * 1024 * 1024) { http_response_code(400); echo json_encode(['error'=>'Fichier trop lourd']); break; }
    // Vérifier quota 50 Mo
    $st3 = $db->prepare("SELECT COALESCE(SUM(file_size),0) as total FROM vault_files WHERE user_id=:uid");
    $st3->execute([':uid'=>$uid]);
    if ((int)$st3->fetch()['total'] + $f['size'] > 52428800) { http_response_code(400); echo json_encode(['error'=>'Quota dépassé (50 Mo max)']); break; }
    $dir = __DIR__.'/uploads/vault/'.$uid.'/';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $htaccess = $dir . '.htaccess';
    if (!file_exists($htaccess)) file_put_contents($htaccess, "Deny from all\n");
    $fn = 'vf_'.time().'_'.bin2hex(random_bytes(8)).'.enc';
    if (!move_uploaded_file($f['tmp_name'], $dir.$fn)) { http_response_code(500); echo json_encode(['error'=>'Erreur upload']); break; }
    $originalName = $_POST['original_name'] ?? 'fichier';
    $fileSize = (int)($_POST['file_size'] ?? $f['size']);
    $db->prepare("INSERT INTO vault_files (user_id,filename,original_name,file_size) VALUES (:uid,:fn,:on,:fs)")
       ->execute([':uid'=>$uid,':fn'=>$fn,':on'=>$originalName,':fs'=>$fileSize]);
    $id = (int)$db->lastInsertId();
    echo json_encode(['success'=>true,'file'=>['id'=>$id,'original_name'=>$originalName,'file_size'=>$fileSize,'created_at'=>date('c')]]);
    break;

case 'vault_download':
    if (!$uid || $role !== 'coach') { http_response_code(403); exit; }
    $fileId = (int)($_GET['file_id'] ?? 0);
    $db = getDB();
    $st = $db->prepare("SELECT filename FROM vault_files WHERE id=:id AND user_id=:uid");
    $st->execute([':id'=>$fileId,':uid'=>$uid]);
    $row = $st->fetch();
    if (!$row) { http_response_code(404); echo json_encode(['error'=>'Fichier introuvable']); exit; }
    $path = __DIR__.'/uploads/vault/'.$uid.'/'.$row['filename'];
    if (!file_exists($path)) { http_response_code(404); echo json_encode(['error'=>'Fichier manquant']); exit; }
    header('Content-Type: application/octet-stream');
    header('Content-Length: '.filesize($path));
    header('Cache-Control: no-store');
    readfile($path);
    exit;

case 'vault_delete':
    if (!$uid || $role !== 'coach') { http_response_code(403); echo json_encode(['error'=>'Coach requis']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $fileId = (int)($in['id'] ?? 0);
    $db = getDB();
    $st = $db->prepare("SELECT filename FROM vault_files WHERE id=:id AND user_id=:uid");
    $st->execute([':id'=>$fileId,':uid'=>$uid]);
    $row = $st->fetch();
    if ($row) {
        $path = __DIR__.'/uploads/vault/'.$uid.'/'.$row['filename'];
        if (file_exists($path)) unlink($path);
        $db->prepare("DELETE FROM vault_files WHERE id=:id AND user_id=:uid")
           ->execute([':id'=>$fileId,':uid'=>$uid]);
    }
    echo json_encode(['success'=>true]);
    break;

// ═══ TCHAT PUBLIC (connectés : post + suppr propre ; coach : suppr tout) ═══
case 'chat_list':
    $db = getDB();
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            display_name VARCHAR(120) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'parent',
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_created (created_at),
            INDEX idx_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    } catch (Exception $e) {}
    // Nettoyage auto : supprimer les messages de plus de 2 mois
    try { $db->exec("DELETE FROM chat_messages WHERE created_at < DATE_SUB(NOW(), INTERVAL 2 MONTH)"); } catch (Exception $e) {}
    $limit = min(200, max(20, (int)($_GET['limit'] ?? 100)));
    $st = $db->query("SELECT id, user_id, display_name, role, content, created_at FROM chat_messages ORDER BY created_at DESC LIMIT " . $limit);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'messages' => $rows, 'user_id' => $uid, 'is_admin' => ($role === 'coach')]);
    break;

case 'chat_post':
    if (!$uid) { http_response_code(403); echo json_encode(['error' => 'Connecte-toi pour poster']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $content = trim((string)($in['content'] ?? ''));
    if ($content === '') { echo json_encode(['error' => 'Message vide']); break; }
    if (mb_strlen($content) > 8000) { echo json_encode(['error' => 'Message trop long']); break; }
    $displayName = isset($_SESSION['display_name']) ? $_SESSION['display_name'] : 'Utilisateur';
    $userRole = $role ?: 'parent';
    $db = getDB();
    try {
        $db->exec("CREATE TABLE IF NOT EXISTS chat_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            display_name VARCHAR(120) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'parent',
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_created (created_at),
            INDEX idx_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    } catch (Exception $e) {}
    $st = $db->prepare("INSERT INTO chat_messages (user_id, display_name, role, content) VALUES (:uid, :dn, :role, :content)");
    $st->execute([':uid' => $uid, ':dn' => $displayName, ':role' => $userRole, ':content' => $content]);
    $id = (int)$db->lastInsertId();
    $row = $db->query("SELECT id, user_id, display_name, role, content, created_at FROM chat_messages WHERE id = $id")->fetch(PDO::FETCH_ASSOC);
    echo json_encode(['success' => true, 'message' => $row]);
    break;

case 'chat_delete':
    if (!$uid) { http_response_code(403); echo json_encode(['error' => 'Non connecté']); break; }
    $in = json_decode(file_get_contents('php://input'), true);
    $msgId = (int)($in['id'] ?? 0);
    if ($msgId <= 0) { echo json_encode(['error' => 'ID invalide']); break; }
    $db = getDB();
    $st = $db->prepare("SELECT user_id FROM chat_messages WHERE id = :id");
    $st->execute([':id' => $msgId]);
    $row = $st->fetch();
    if (!$row) { echo json_encode(['error' => 'Message introuvable']); break; }
    $canDelete = ($row['user_id'] == $uid) || ($role === 'coach');
    if (!$canDelete) { http_response_code(403); echo json_encode(['error' => 'Tu ne peux supprimer que tes messages']); break; }
    $db->prepare("DELETE FROM chat_messages WHERE id = :id")->execute([':id' => $msgId]);
    echo json_encode(['success' => true]);
    break;

default: http_response_code(400); echo json_encode(['error'=>'Action inconnue']); break;
}
