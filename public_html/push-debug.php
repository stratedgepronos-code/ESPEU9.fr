<?php
// ═══════════════════════════════════════════════════════════════════
// ESPE BASKET U9 — Push Notification Debugger
// ═══════════════════════════════════════════════════════════════════
// TEMPORAIRE: Supprime ce fichier après utilisation !
// USAGE: Visite https://espeu9.fr/push-debug.php
// ═══════════════════════════════════════════════════════════════════

require_once 'config.php';
require_once 'web_push.php';

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Push Debug ESPE U9</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; max-width: 800px; margin: 0 auto; }
        h1 { color: #4ade80; } h2 { color: #60a5fa; border-bottom: 1px solid #333; padding-bottom: 5px; margin-top: 30px; }
        .ok { color: #4ade80; } .ok::before { content: "OK "; }
        .fail { color: #f87171; } .fail::before { content: "ERREUR "; }
        .warn { color: #fbbf24; } .warn::before { content: "ATTENTION "; }
        .info { color: #93c5fd; } .info::before { content: "INFO "; }
        pre { background: #0f0f23; padding: 10px; border-radius: 5px; overflow-x: auto; font-size: 12px; }
        button { background: #4ade80; color: #000; border: none; padding: 12px 24px; font-size: 16px; border-radius: 5px; cursor: pointer; margin: 10px 5px; }
        button:hover { background: #22c55e; }
        .result { background: #0f0f23; padding: 15px; border-radius: 5px; margin: 10px 0; white-space: pre-wrap; word-break: break-all; }
    </style>
</head>
<body>
<h1>Push Debug ESPE U9</h1>

<?php
// 1. PHP
echo "<h2>1. Environnement PHP</h2>";
echo "<p class='ok'>PHP " . PHP_VERSION . "</p>";
echo "<p class='" . (extension_loaded('openssl') ? 'ok' : 'fail') . "'>Extension openssl " . (extension_loaded('openssl') ? 'OK' : 'MANQUANTE') . "</p>";
echo "<p class='" . (function_exists('openssl_pkey_derive') ? 'ok' : 'fail') . "'>openssl_pkey_derive() " . (function_exists('openssl_pkey_derive') ? 'disponible' : 'MANQUANTE (PHP 7.3+)') . "</p>";
echo "<p class='" . (function_exists('hash_hkdf') ? 'ok' : 'fail') . "'>hash_hkdf() " . (function_exists('hash_hkdf') ? 'disponible' : 'MANQUANTE (PHP 7.1.2+)') . "</p>";
echo "<p class='" . (in_array('aes-128-gcm', openssl_get_cipher_methods()) ? 'ok' : 'fail') . "'>aes-128-gcm</p>";

// 2. EC key test
echo "<h2>2. Test cle EC P-256</h2>";
$testKey = @openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
if ($testKey) {
    $d = openssl_pkey_get_details($testKey);
    echo "<p class='ok'>Cle EC generee (x:" . strlen($d['ec']['x']) . " y:" . strlen($d['ec']['y']) . " bytes)</p>";
} else {
    echo "<p class='fail'>Echec: " . openssl_error_string() . "</p>";
}

// 3. VAPID keys
echo "<h2>3. Cles VAPID</h2>";
$pubRaw = base64url_decode(VAPID_PUBLIC_KEY);
$privRaw = base64url_decode(VAPID_PRIVATE_KEY);
$pubOk = (strlen($pubRaw) === 65 && VAPID_PUBLIC_KEY !== 'COLLE_TA_CLE_PUBLIQUE_VAPID_ICI');
$privOk = (strlen($privRaw) === 32 && VAPID_PRIVATE_KEY !== 'COLLE_TA_CLE_PRIVEE_VAPID_ICI');
echo "<p class='" . ($pubOk ? 'ok' : 'fail') . "'>PUBLIC_KEY: " . strlen($pubRaw) . " bytes" . ($pubOk ? '' : ' — INVALIDE !') . "</p>";
echo "<p class='" . ($privOk ? 'ok' : 'fail') . "'>PRIVATE_KEY: " . strlen($privRaw) . " bytes" . ($privOk ? '' : ' — INVALIDE !') . "</p>";

// Test PEM
$pemResult = wpCreateVapidPrivateKeyPem();
if (isset($pemResult['error'])) {
    echo "<p class='fail'>PEM: " . $pemResult['error'] . "</p>";
} else {
    $vpk = openssl_pkey_get_private($pemResult['pem']);
    echo "<p class='" . ($vpk ? 'ok' : 'fail') . "'>PEM VAPID " . ($vpk ? 'charge' : 'ERREUR: ' . openssl_error_string()) . "</p>";
}

// 4. JWT test
echo "<h2>4. Signature VAPID JWT</h2>";
$tv = wpCreateVapidAuth('https://fcm.googleapis.com/fcm/send/test');
if (isset($tv['error'])) {
    echo "<p class='fail'>" . $tv['error'] . "</p>";
} else {
    echo "<p class='ok'>JWT signe avec succes</p>";
}

// 5. Encryption test
echo "<h2>5. Test encryption payload</h2>";
if ($testKey) {
    $fd = openssl_pkey_get_details($testKey);
    $fp = "\x04" . str_pad($fd['ec']['x'], 32, "\x00", STR_PAD_LEFT) . str_pad($fd['ec']['y'], 32, "\x00", STR_PAD_LEFT);
    $fa = random_bytes(16);
    $enc = wpEncryptPayload('{"title":"Test","body":"Hello"}', $fp, $fa);
    if (isset($enc['error'])) {
        echo "<p class='fail'>Encryption: " . $enc['error'] . "</p>";
    } else {
        echo "<p class='ok'>Encryption reussie (" . strlen($enc['body']) . " bytes)</p>";
    }
}

// 6. Subscribers
echo "<h2>6. Abonnes push</h2>";
try {
    $db = getDB();
    $st = $db->query("SELECT * FROM push_subscriptions");
    $subs = $st->fetchAll(PDO::FETCH_ASSOC);
    echo "<p class='" . (count($subs) > 0 ? 'ok' : 'warn') . "'>" . count($subs) . " abonne(s)</p>";
    foreach ($subs as $s) {
        $host = parse_url($s['endpoint'], PHP_URL_HOST);
        echo "<p class='info'>#{$s['id']} user#{$s['user_id']} — {$host} — p256dh:" . strlen(base64url_decode($s['p256dh'])) . "B auth:" . strlen(base64url_decode($s['auth'])) . "B</p>";
    }
} catch (Exception $e) {
    echo "<p class='fail'>" . $e->getMessage() . "</p>";
    $subs = [];
}

// 7. sw.js check
echo "<h2>7. Service Worker</h2>";
$swPath = __DIR__ . '/sw.js';
if (file_exists($swPath)) {
    $sw = file_get_contents($swPath);
    echo "<p class='ok'>sw.js existe (" . strlen($sw) . " bytes, modifie " . date('d/m H:i', filemtime($swPath)) . ")</p>";
    echo "<p class='" . (strpos($sw, "addEventListener('push'") !== false ? 'ok' : 'fail') . "'>Handler push: " . (strpos($sw, "addEventListener('push'") !== false ? 'present' : 'ABSENT !') . "</p>";
    echo "<p class='" . (strpos($sw, 'showNotification') !== false ? 'ok' : 'fail') . "'>showNotification: " . (strpos($sw, 'showNotification') !== false ? 'present' : 'ABSENT !') . "</p>";
    echo "<p class='" . (strpos($sw, 'notificationclick') !== false ? 'ok' : 'fail') . "'>Handler click: " . (strpos($sw, 'notificationclick') !== false ? 'present' : 'ABSENT') . "</p>";
    if (preg_match("/SW_VERSION\s*=\s*'([^']+)'/", $sw, $m)) echo "<p class='info'>Version: v{$m[1]}</p>";
} else {
    echo "<p class='fail'>sw.js MANQUANT dans " . __DIR__ . "</p>";
}

// .htaccess check
$ht = @file_get_contents(__DIR__ . '/.htaccess');
echo "<p class='" . ($ht && strpos($ht, 'sw.js') !== false ? 'ok' : 'warn') . "'>.htaccess regle sw.js: " . ($ht && strpos($ht, 'sw.js') !== false ? 'presente' : 'ABSENTE — ajoute no-cache pour sw.js') . "</p>";

// 8. Send test
echo "<h2>8. Envoyer un test</h2>";

if (isset($_POST['send_test']) && count($subs) > 0) {
    $payload = [
        'title' => '🏀 Test ESPE U9',
        'body'  => 'Si tu vois CE TEXTE, les notifications marchent parfaitement !',
        'icon'  => '/logo-espe.png',
        'badge' => '/logo-espe.png',
        'data'  => ['url' => 'https://espeu9.fr/#accueil']
    ];
    foreach ($subs as $sub) {
        $subscription = ['endpoint' => $sub['endpoint'], 'keys' => ['p256dh' => $sub['p256dh'], 'auth' => $sub['auth']]];
        $result = sendWebPush($subscription, $payload);
        if ($result['success']) {
            echo "<p class='ok'>Envoye a #{$sub['id']} — HTTP {$result['code']}</p>";
        } else {
            echo "<p class='fail'>Echec #{$sub['id']} — {$result['error']}</p>";
            if (($result['code'] ?? 0) == 404 || ($result['code'] ?? 0) == 410) {
                $db->prepare("DELETE FROM push_subscriptions WHERE id=:id")->execute([':id' => $sub['id']]);
                echo "<p class='warn'>Subscription #{$sub['id']} supprimee (expiree)</p>";
            }
        }
    }
}
?>

<form method="POST">
    <button type="submit" name="send_test" value="1"<?php echo count($subs) === 0 ? ' disabled style="opacity:0.5"' : ''; ?>>
        Envoyer une notification de test (<?php echo count($subs); ?> abonne(s))
    </button>
</form>

<h2>9. Resume</h2>
<?php
$issues = wpCheckRequirements();
if (empty($issues)) {
    echo "<p class='ok' style='font-size:16px;'>Tout est pret !</p>";
    echo "<p class='info'>Si ca ne marche toujours pas, sur ton telephone : Chrome > Parametres > Sites > espeu9.fr > Effacer et reinitialiser. Puis recharge le site et reactive les notifs.</p>";
} else {
    foreach ($issues as $i) echo "<p class='fail'>{$i}</p>";
}
?>

<p style="color:#f87171;margin-top:40px;font-size:14px;"><strong>SUPPRIME CE FICHIER apres utilisation !</strong> (push-debug.php)</p>
</body></html>
