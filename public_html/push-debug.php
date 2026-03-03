<?php
date_default_timezone_set('Europe/Paris');
require_once 'config.php';
require_once 'web_push.php';
session_start();
if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'coach') {
    http_response_code(403);
    die('<h1>Acc&egrave;s interdit</h1><p>Connecte-toi en tant que coach pour acc&eacute;der au debug push.</p><a href="gate.html">Connexion</a>');
}
header('Content-Type: text/html; charset=utf-8');
?><!DOCTYPE html>
<html><head>
<title>Push Debug ESPE U9</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;padding:20px;max-width:800px;margin:0 auto}
h1{color:#4ade80}h2{color:#60a5fa;border-bottom:1px solid #333;padding-bottom:5px;margin-top:30px}
.ok{color:#4ade80}.ok::before{content:"✅ "}
.fail{color:#f87171}.fail::before{content:"❌ "}
.warn{color:#fbbf24}.warn::before{content:"⚠️ "}
.info{color:#93c5fd}.info::before{content:"ℹ️ "}
pre{background:#0f0f23;padding:10px;border-radius:5px;overflow-x:auto;font-size:12px;white-space:pre-wrap;word-break:break-all}
button{background:#4ade80;color:#000;border:none;padding:12px 24px;font-size:16px;border-radius:5px;cursor:pointer;margin:10px 5px}
button:hover{background:#22c55e}
button:disabled{opacity:0.5;cursor:not-allowed}
.log-box{background:#0f0f23;border:1px solid #333;border-radius:8px;padding:12px;margin:8px 0;font-size:12px}
</style>
</head><body>
<h1>🔔 Push Debug ESPE U9 v3</h1>

<?php
// 1. PHP
echo "<h2>1. Environnement PHP</h2>";
echo "<p class='ok'>PHP " . PHP_VERSION . "</p>";

$checks = [
    ['extension_loaded("openssl")', extension_loaded('openssl'), 'openssl'],
    ['function_exists("openssl_pkey_derive")', function_exists('openssl_pkey_derive'), 'openssl_pkey_derive (PHP 7.3+)'],
    ['function_exists("openssl_pkey_new")', function_exists('openssl_pkey_new'), 'openssl_pkey_new'],
    ['aes-128-gcm', in_array('aes-128-gcm', openssl_get_cipher_methods()), 'aes-128-gcm cipher'],
    ['function_exists("curl_init")', function_exists('curl_init'), 'cURL'],
];
foreach ($checks as $c) {
    echo "<p class='" . ($c[1] ? 'ok' : 'fail') . "'>{$c[2]}</p>";
}

// 2. EC key
echo "<h2>2. Test clé EC P-256</h2>";
$testKey = @openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
if ($testKey) {
    $d = openssl_pkey_get_details($testKey);
    echo "<p class='ok'>Clé EC générée (x:" . strlen($d['ec']['x']) . " y:" . strlen($d['ec']['y']) . ")</p>";
} else {
    echo "<p class='fail'>Échec: " . openssl_error_string() . "</p>";
}

// 3. VAPID keys
echo "<h2>3. Clés VAPID</h2>";
$pubRaw = base64url_decode(VAPID_PUBLIC_KEY);
$privRaw = base64url_decode(VAPID_PRIVATE_KEY);
echo "<p class='" . (strlen($pubRaw) === 65 ? 'ok' : 'fail') . "'>Public key: " . strlen($pubRaw) . " bytes</p>";
echo "<p class='" . (strlen($privRaw) === 32 ? 'ok' : 'fail') . "'>Private key: " . strlen($privRaw) . " bytes</p>";

// Build PEM and test
$der = hex2bin('30770201010420') . $privRaw . hex2bin('a00a06082a8648ce3d030107a14403420004') . $pubRaw;
$pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64) . "-----END EC PRIVATE KEY-----\n";
$vpk = openssl_pkey_get_private($pem);
echo "<p class='" . ($vpk ? 'ok' : 'fail') . "'>PEM chargée: " . ($vpk ? 'oui' : openssl_error_string()) . "</p>";

// 4. JWT
echo "<h2>4. Signature JWT VAPID</h2>";
$jwt = wpCreateJWT('https://fcm.googleapis.com');
if ($jwt) {
    echo "<p class='ok'>JWT signé avec succès</p>";
    echo "<p class='info'>Token: " . substr($jwt, 0, 50) . "...</p>";
} else {
    echo "<p class='fail'>JWT échoué</p>";
    echo "<div class='log-box'>" . implode("<br>", getPushLog()) . "</div>";
}

// 5. Encryption test
echo "<h2>5. Test encryption</h2>";
if ($testKey) {
    $fd = openssl_pkey_get_details($testKey);
    $fakeP256dh = "\x04" . str_pad($fd['ec']['x'], 32, "\x00", STR_PAD_LEFT) . str_pad($fd['ec']['y'], 32, "\x00", STR_PAD_LEFT);
    $fakeAuth = random_bytes(16);
    $enc = wpEncrypt('{"title":"Test","body":"Hello ESPE U9!"}', base64url_encode($fakeP256dh), base64url_encode($fakeAuth));
    if ($enc) {
        echo "<p class='ok'>Encryption réussie (" . strlen($enc) . " bytes)</p>";
    } else {
        echo "<p class='fail'>Encryption échouée</p>";
        echo "<div class='log-box'>" . implode("<br>", getPushLog()) . "</div>";
    }
} else {
    echo "<p class='fail'>Pas de clé EC pour tester</p>";
}

// 6. Subscribers
echo "<h2>6. Abonnés push</h2>";
$subs = [];
try {
    $db = getDB();
    $st = $db->query("SELECT ps.*, u.display_name, u.role FROM push_subscriptions ps LEFT JOIN users u ON u.id = ps.user_id ORDER BY ps.created_at DESC");
    $subs = $st->fetchAll(PDO::FETCH_ASSOC);
    echo "<p class='" . (count($subs) > 0 ? 'ok' : 'warn') . "'>" . count($subs) . " abonné(s)</p>";
    foreach ($subs as $s) {
        $host = parse_url($s['endpoint'], PHP_URL_HOST);
        $p256dhLen = strlen(base64url_decode($s['p256dh']));
        $authLen = strlen(base64url_decode($s['auth']));
        $valid = ($p256dhLen === 65 && $authLen === 16);
        echo "<p class='" . ($valid ? 'info' : 'fail') . "'>#{$s['id']} — " . htmlspecialchars($s['display_name'] ?? 'user#' . $s['user_id']) . " ({$s['role']}) — {$host} — p256dh:{$p256dhLen}B auth:{$authLen}B" . ($valid ? '' : ' ⚠️ INVALIDE') . "</p>";
    }
} catch (Exception $e) {
    echo "<p class='fail'>" . htmlspecialchars($e->getMessage()) . "</p>";
}

// 7. sw.js
echo "<h2>7. Service Worker</h2>";
$swPath = __DIR__ . '/sw.js';
if (file_exists($swPath)) {
    $sw = file_get_contents($swPath);
    echo "<p class='ok'>sw.js (" . strlen($sw) . " bytes, modifié " . date('d/m H:i', filemtime($swPath)) . ")</p>";
    echo "<p class='" . (strpos($sw, "addEventListener('push'") !== false ? 'ok' : 'fail') . "'>Handler push</p>";
    echo "<p class='" . (strpos($sw, 'showNotification') !== false ? 'ok' : 'fail') . "'>showNotification</p>";
} else {
    echo "<p class='fail'>sw.js MANQUANT</p>";
}

// 8. Send test
echo "<h2>8. Envoyer un test push</h2>";

if (isset($_POST['send_test']) && count($subs) > 0) {
    $payload = [
        'title' => '🏀 Test ESPE U9',
        'body'  => 'Si tu vois ce texte avec le logo, les notifications marchent !',
        'icon'  => 'https://espeu9.fr/images/logo-espe.png',
        'badge' => 'https://espeu9.fr/images/logo-espe.png',
        'data'  => ['url' => 'https://espeu9.fr/']
    ];

    $targetId = isset($_POST['sub_id']) ? (int)$_POST['sub_id'] : 0;

    foreach ($subs as $sub) {
        if ($targetId && (int)$sub['id'] !== $targetId) continue;

        echo "<h3 style='color:#fbbf24'>→ #{$sub['id']} — " . htmlspecialchars($sub['display_name'] ?? 'user#' . $sub['user_id']) . "</h3>";
        $subscription = ['endpoint' => $sub['endpoint'], 'keys' => ['p256dh' => $sub['p256dh'], 'auth' => $sub['auth']]];
        $result = sendWebPush($subscription, $payload);

        if ($result['success']) {
            echo "<p class='ok'>Envoyé — HTTP {$result['code']}</p>";
        } else {
            echo "<p class='fail'>Échec — " . htmlspecialchars($result['error'] ?? 'inconnu') . " (HTTP " . ($result['code'] ?? '?') . ")</p>";
            if (($result['code'] ?? 0) == 404 || ($result['code'] ?? 0) == 410) {
                $db->prepare("DELETE FROM push_subscriptions WHERE id=:id")->execute([':id' => $sub['id']]);
                echo "<p class='warn'>Subscription expirée → supprimée</p>";
            }
        }
        if (!empty($result['log'])) {
            echo "<div class='log-box'><strong>Log détaillé :</strong><br>" . implode("<br>", array_map('htmlspecialchars', $result['log'])) . "</div>";
        }
        if (!empty($result['response'])) {
            echo "<div class='log-box'><strong>Réponse serveur :</strong><br>" . htmlspecialchars($result['response']) . "</div>";
        }
    }
}
?>

<form method="POST">
    <button type="submit" name="send_test" value="1"<?php echo count($subs) === 0 ? ' disabled' : ''; ?>>
        🔔 Envoyer un test à TOUS (<?php echo count($subs); ?> abonné(s))
    </button>
</form>

<?php if (count($subs) > 1): ?>
<form method="POST" style="display:inline">
    <select name="sub_id" style="padding:10px;border-radius:5px;background:#0f0f23;color:#e0e0e0;border:1px solid #333">
        <?php foreach ($subs as $s): ?>
        <option value="<?php echo $s['id']; ?>">#<?php echo $s['id']; ?> — <?php echo htmlspecialchars($s['display_name'] ?? 'user#' . $s['user_id']); ?></option>
        <?php endforeach; ?>
    </select>
    <button type="submit" name="send_test" value="1">🔔 Envoyer à cet abonné</button>
</form>
<?php endif; ?>

<h2>9. Résumé</h2>
<?php
$issues = [];
if (!extension_loaded('openssl')) $issues[] = 'openssl manquant';
if (!function_exists('openssl_pkey_derive')) $issues[] = 'openssl_pkey_derive() indisponible — PHP 7.3+ requis';
if (!in_array('aes-128-gcm', openssl_get_cipher_methods())) $issues[] = 'aes-128-gcm non supporté';
if (!function_exists('curl_init')) $issues[] = 'cURL manquant';
if (!$testKey) $issues[] = 'Impossible de générer une clé EC P-256';
if (!$vpk) $issues[] = 'Clé VAPID PEM invalide';
if (!$jwt) $issues[] = 'Signature JWT VAPID échouée';

if (empty($issues)) {
    echo "<p class='ok' style='font-size:16px'>Tout est prêt côté serveur !</p>";
    echo "<p class='info'>Si ça ne marche pas sur le téléphone :<br>
    1. Chrome → ⋮ → Paramètres → Notifications → espeu9.fr → Autoriser<br>
    2. Si déjà autorisé : Paramètres > Sites > espeu9.fr > Effacer et réinitialiser<br>
    3. Reviens sur espeu9.fr et réactive les notifs dans ton compte</p>";
} else {
    foreach ($issues as $i) echo "<p class='fail'>$i</p>";
}
?>

<p style="color:#f87171;margin-top:40px;font-size:14px"><strong>⚠️ Supprime ce fichier après utilisation !</strong></p>
</body></html>
