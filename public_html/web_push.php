<?php
/**
 * ESPE BASKET U9 — Web Push v3.0
 * Implémentation robuste avec logging d'erreurs
 */

if (!defined('VAPID_PUBLIC_KEY'))  define('VAPID_PUBLIC_KEY',  'BKux74q_3ayYXtGDcNlZUN0qwZMkcPX93qxNY9hpngeH2Mpk-oLytRRfzIfyy2V8TM1cmc9CyrqNmGrtgvHtVuA');
if (!defined('VAPID_PRIVATE_KEY')) define('VAPID_PRIVATE_KEY', 'ZKFkKhcGwueezbCjZNAmnyyC_Xx326CO52xHkAVbQbU');
if (!defined('VAPID_SUBJECT'))    define('VAPID_SUBJECT',     'https://espeu9.fr');

$_PUSH_LOG = [];

function pushLog($msg) {
    global $_PUSH_LOG;
    $_PUSH_LOG[] = $msg;
}

function getPushLog() {
    global $_PUSH_LOG;
    return $_PUSH_LOG;
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

function sendWebPush($subscription, $payload) {
    global $_PUSH_LOG;
    $_PUSH_LOG = [];

    $endpoint = $subscription['endpoint'] ?? '';
    $p256dh   = $subscription['keys']['p256dh'] ?? '';
    $auth     = $subscription['keys']['auth'] ?? '';

    if (!$endpoint || !$p256dh || !$auth) {
        pushLog('ERREUR: données subscription incomplètes');
        return ['success' => false, 'error' => 'Subscription data missing', 'log' => getPushLog()];
    }

    $payloadJson = is_string($payload) ? $payload : json_encode($payload, JSON_UNESCAPED_UNICODE);
    pushLog('Payload: ' . strlen($payloadJson) . ' bytes');

    // 1) Encrypt
    $encrypted = wpEncrypt($payloadJson, $p256dh, $auth);
    if (!$encrypted) {
        return ['success' => false, 'error' => 'Encryption failed', 'log' => getPushLog()];
    }
    pushLog('Encryption OK: ' . strlen($encrypted) . ' bytes');

    // 2) VAPID
    $audience = parse_url($endpoint, PHP_URL_SCHEME) . '://' . parse_url($endpoint, PHP_URL_HOST);
    $jwt = wpCreateJWT($audience);
    if (!$jwt) {
        return ['success' => false, 'error' => 'VAPID JWT failed', 'log' => getPushLog()];
    }
    pushLog('JWT OK');

    // 3) HTTP POST
    $headers = [
        'Content-Type: application/octet-stream',
        'Content-Encoding: aes128gcm',
        'Content-Length: ' . strlen($encrypted),
        'TTL: 2419200',
        'Urgency: high',
        'Authorization: vapid t=' . $jwt . ', k=' . VAPID_PUBLIC_KEY,
    ];

    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $encrypted,
        CURLOPT_HTTPHEADER     => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr  = curl_error($ch);
    curl_close($ch);

    if ($curlErr) {
        pushLog('CURL error: ' . $curlErr);
        return ['success' => false, 'error' => 'curl: ' . $curlErr, 'code' => 0, 'log' => getPushLog()];
    }

    pushLog("HTTP $httpCode — response: " . substr($response, 0, 200));

    return [
        'success'  => ($httpCode >= 200 && $httpCode < 300),
        'code'     => $httpCode,
        'response' => $response,
        'log'      => getPushLog(),
    ];
}

/**
 * AES-128-GCM encryption per RFC 8291 / RFC 8188
 */
function wpEncrypt($payload, $userPubB64, $userAuthB64) {
    $uaPublic = base64url_decode($userPubB64);
    $uaAuth   = base64url_decode($userAuthB64);

    if (strlen($uaPublic) !== 65) { pushLog('p256dh décodé: ' . strlen($uaPublic) . ' bytes (attendu 65)'); return false; }
    if (strlen($uaAuth)   !== 16) { pushLog('auth décodé: ' . strlen($uaAuth) . ' bytes (attendu 16)');     return false; }

    // Ephemeral EC key pair (application server)
    $asKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    if (!$asKey) { pushLog('openssl_pkey_new() failed: ' . openssl_error_string()); return false; }

    $asDetails = openssl_pkey_get_details($asKey);
    $asPublic  = "\x04"
        . str_pad($asDetails['ec']['x'], 32, "\x00", STR_PAD_LEFT)
        . str_pad($asDetails['ec']['y'], 32, "\x00", STR_PAD_LEFT);

    pushLog('Ephemeral key OK: ' . strlen($asPublic) . ' bytes');

    // ECDH: shared secret
    $ecdhSecret = wpECDH($asKey, $uaPublic);
    if ($ecdhSecret === false) { pushLog('ECDH failed'); return false; }
    pushLog('ECDH OK: ' . strlen($ecdhSecret) . ' bytes');

    // Salt (random 16 bytes)
    $salt = random_bytes(16);

    // ── Key derivation (RFC 8291 §3.4) ──
    // Step 1: IKM from auth secret + ECDH
    $keyInfo = "WebPush: info\x00" . $uaPublic . $asPublic;
    $ikm = wpHKDF($uaAuth, $ecdhSecret, $keyInfo, 32);

    // Step 2: PRK from salt + IKM (RFC 8188)
    $prk = hash_hmac('sha256', $ikm, $salt, true);

    // Step 3: Content encryption key & nonce
    $cek   = wpHKDFExpand($prk, "Content-Encoding: aes128gcm\x00", 16);
    $nonce = wpHKDFExpand($prk, "Content-Encoding: nonce\x00", 12);

    // ── Encrypt (AES-128-GCM) ──
    // Padding delimiter: 0x02 = final record
    $padded = $payload . "\x02";

    $tag = '';
    $ciphertext = openssl_encrypt($padded, 'aes-128-gcm', $cek, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($ciphertext === false) { pushLog('AES-GCM encrypt failed: ' . openssl_error_string()); return false; }

    pushLog('AES-GCM OK: cipher=' . strlen($ciphertext) . ' tag=' . strlen($tag));

    // ── Build aes128gcm content (RFC 8188 §2) ──
    // Header: salt(16) || rs(4, uint32 BE) || idlen(1) || keyid(idlen)
    $rs     = pack('N', 4096);
    $header = $salt . $rs . chr(65) . $asPublic;

    return $header . $ciphertext . $tag;
}

/**
 * ECDH shared secret via openssl_pkey_derive
 */
function wpECDH($localPrivKey, $remotePublicKeyBin) {
    if (!function_exists('openssl_pkey_derive')) {
        pushLog('openssl_pkey_derive() non disponible (PHP 7.3+ requis)');
        return false;
    }

    $x = substr($remotePublicKeyBin, 1, 32);
    $y = substr($remotePublicKeyBin, 33, 32);

    // ASN.1 DER for EC public key on P-256
    $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200')
         . "\x04" . $x . $y;

    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64) . "-----END PUBLIC KEY-----\n";
    $remotePubKey = openssl_pkey_get_public($pem);
    if (!$remotePubKey) {
        pushLog('Clé publique remote invalide: ' . openssl_error_string());
        return false;
    }

    $secret = openssl_pkey_derive($localPrivKey, $remotePubKey, 32);
    if ($secret === false) {
        pushLog('openssl_pkey_derive() a échoué: ' . openssl_error_string());
        return false;
    }
    return $secret;
}

/**
 * HKDF Extract + Expand (RFC 5869)
 */
function wpHKDF($salt, $ikm, $info, $length) {
    $prk = hash_hmac('sha256', $ikm, $salt, true);
    return wpHKDFExpand($prk, $info, $length);
}

function wpHKDFExpand($prk, $info, $length) {
    $t   = '';
    $out = '';
    for ($i = 1; strlen($out) < $length; $i++) {
        $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
        $out .= $t;
    }
    return substr($out, 0, $length);
}

/**
 * Create VAPID JWT (ES256)
 */
function wpCreateJWT($audience) {
    $header  = base64url_encode('{"typ":"JWT","alg":"ES256"}');
    $claims  = base64url_encode(json_encode([
        'aud' => $audience,
        'exp' => time() + 86400,
        'sub' => VAPID_SUBJECT,
    ]));
    $unsigned = $header . '.' . $claims;

    // Build EC private key PEM
    $privRaw = base64url_decode(VAPID_PRIVATE_KEY);
    $pubRaw  = base64url_decode(VAPID_PUBLIC_KEY);

    if (strlen($privRaw) !== 32) { pushLog('VAPID private key: ' . strlen($privRaw) . ' bytes (attendu 32)'); return false; }
    if (strlen($pubRaw)  !== 65) { pushLog('VAPID public key: '  . strlen($pubRaw)  . ' bytes (attendu 65)'); return false; }

    $der = hex2bin('30770201010420')
         . $privRaw
         . hex2bin('a00a06082a8648ce3d030107a14403420004')
         . $pubRaw;

    $pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64) . "-----END EC PRIVATE KEY-----\n";
    $key = openssl_pkey_get_private($pem);
    if (!$key) { pushLog('VAPID PEM invalide: ' . openssl_error_string()); return false; }

    $sig = '';
    if (!openssl_sign($unsigned, $sig, $key, OPENSSL_ALGO_SHA256)) {
        pushLog('openssl_sign failed: ' . openssl_error_string());
        return false;
    }

    // DER → raw R||S (64 bytes)
    $raw = wpDerToRaw($sig);
    if (!$raw || strlen($raw) !== 64) { pushLog('Signature raw: ' . ($raw ? strlen($raw) : 'false') . ' bytes (attendu 64)'); return false; }

    return $unsigned . '.' . base64url_encode($raw);
}

/**
 * Convert DER ECDSA signature → R || S (each 32 bytes, big-endian)
 */
function wpDerToRaw($der) {
    if (strlen($der) < 8) return false;
    if (ord($der[0]) !== 0x30) return false;

    $offset = 2;

    // R
    if (ord($der[$offset]) !== 0x02) return false;
    $rLen = ord($der[$offset + 1]);
    $r = substr($der, $offset + 2, $rLen);
    $offset += 2 + $rLen;

    // S
    if ($offset >= strlen($der) || ord($der[$offset]) !== 0x02) return false;
    $sLen = ord($der[$offset + 1]);
    $s = substr($der, $offset + 2, $sLen);

    // Normalize to 32 bytes each
    $r = str_pad(ltrim($r, "\x00"), 32, "\x00", STR_PAD_LEFT);
    $s = str_pad(ltrim($s, "\x00"), 32, "\x00", STR_PAD_LEFT);

    return $r . $s;
}

// Legacy aliases
function createVapidAuth($audience) { $jwt = wpCreateJWT($audience); return $jwt ? ['token' => $jwt] : false; }
function encryptPayload($p, $pub, $auth) { return ($r = wpEncrypt($p, $pub, $auth)) ? ['ciphertext' => $r] : false; }
