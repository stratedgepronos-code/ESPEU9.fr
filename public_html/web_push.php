<?php
/**
 * ESPE BASKET U9 — Web Push Notification Helper
 * Envoi de notifications push sans bibliothèque externe
 * Nécessite: PHP 7.4+, openssl, gmp (ou bcmath)
 */

// ═══ CLÉS VAPID — Ne pas modifier ═══
define('VAPID_PUBLIC_KEY', 'BKux74q_3ayYXtGDcNlZUN0qwZMkcPX93qxNY9hpngeH2Mpk-oLytRRfzIfyy2V8TM1cmc9CyrqNmGrtgvHtVuA');
define('VAPID_PRIVATE_KEY', 'ZKFkKhcGwueezbCjZNAmnyyC_Xx326CO52xHkAVbQbU');
define('VAPID_SUBJECT', 'https://espeu9.fr');

/**
 * Envoie une notification push à un abonné
 */
function sendWebPush($subscription, $payload) {
    $endpoint = $subscription['endpoint'];
    $userPublicKey = $subscription['keys']['p256dh'];
    $userAuthToken = $subscription['keys']['auth'];
    
    $payloadJson = json_encode($payload);
    
    // Encrypt payload
    $encrypted = encryptPayload($payloadJson, $userPublicKey, $userAuthToken);
    if (!$encrypted) return ['success' => false, 'error' => 'Encryption failed'];
    
    // Build VAPID headers
    $audience = parse_url($endpoint, PHP_URL_SCHEME) . '://' . parse_url($endpoint, PHP_URL_HOST);
    $vapidHeaders = createVapidAuth($audience);
    if (!$vapidHeaders) return ['success' => false, 'error' => 'VAPID auth failed'];
    
    // Send request
    $headers = [
        'Content-Type: application/octet-stream',
        'Content-Encoding: aes128gcm',
        'Content-Length: ' . strlen($encrypted['ciphertext']),
        'TTL: 86400',
        'Urgency: high',
        'Authorization: vapid t=' . $vapidHeaders['token'] . ', k=' . VAPID_PUBLIC_KEY,
    ];
    
    $ch = curl_init($endpoint);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $encrypted['ciphertext'],
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) return ['success' => false, 'error' => $error, 'code' => 0];
    
    return [
        'success' => $httpCode >= 200 && $httpCode < 300,
        'code' => $httpCode,
        'response' => $response
    ];
}

/**
 * Encrypt push payload (aes128gcm)
 */
function encryptPayload($payload, $userPublicKeyB64, $userAuthB64) {
    $userPublicKey = base64url_decode($userPublicKeyB64);
    $userAuth = base64url_decode($userAuthB64);
    
    if (strlen($userPublicKey) !== 65 || strlen($userAuth) !== 16) return false;
    
    // Generate local key pair
    $localKey = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    if (!$localKey) return false;
    
    $localDetails = openssl_pkey_get_details($localKey);
    $localPublicKey = chr(4) . str_pad($localDetails['ec']['x'], 32, chr(0), STR_PAD_LEFT) 
                            . str_pad($localDetails['ec']['y'], 32, chr(0), STR_PAD_LEFT);
    
    // ECDH shared secret
    $sharedSecret = computeECDH($localKey, $userPublicKey);
    if (!$sharedSecret) return false;
    
    // Generate salt
    $salt = random_bytes(16);
    
    // Key derivation
    $ikm = hkdf($userAuth, $sharedSecret, "WebPush: info\0" . $userPublicKey . $localPublicKey, 32);
    $prk = hash_hmac('sha256', $ikm, $salt, true);
    $contentKey = hkdf_expand($prk, "Content-Encoding: aes128gcm\0", 16);
    $nonce = hkdf_expand($prk, "Content-Encoding: nonce\0", 12);
    
    // Pad payload
    $padded = $payload . chr(2) . str_repeat(chr(0), 0);
    
    // Encrypt with AES-128-GCM
    $tag = '';
    $encrypted = openssl_encrypt($padded, 'aes-128-gcm', $contentKey, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
    if ($encrypted === false) return false;
    
    // Build aes128gcm header: salt(16) + rs(4) + idlen(1) + keyid(65) + ciphertext
    $rs = pack('N', 4096);
    $header = $salt . $rs . chr(65) . $localPublicKey;
    
    return ['ciphertext' => $header . $encrypted . $tag];
}

/**
 * Compute ECDH shared secret
 */
function computeECDH($localPrivKey, $remotePublicKeyBin) {
    // Extract x,y from uncompressed point (04 || x || y)
    $x = substr($remotePublicKeyBin, 1, 32);
    $y = substr($remotePublicKeyBin, 33, 32);
    
    // Build PEM for the remote public key
    $hexX = bin2hex($x);
    $hexY = bin2hex($y);
    
    // ASN.1 DER encoding for EC public key on prime256v1
    $der = hex2bin(
        '3059301306072a8648ce3d020106082a8648ce3d030107034200' 
        . '04' . $hexX . $hexY
    );
    
    $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64) . "-----END PUBLIC KEY-----\n";
    $remotePubKey = openssl_pkey_get_public($pem);
    if (!$remotePubKey) return false;
    
    $shared = openssl_pkey_derive($localPrivKey, $remotePubKey, 32);
    return $shared;
}

/**
 * HKDF extract + expand
 */
function hkdf($salt, $ikm, $info, $length) {
    $prk = hash_hmac('sha256', $ikm, $salt, true);
    return hkdf_expand($prk, $info, $length);
}

function hkdf_expand($prk, $info, $length) {
    $output = '';
    $counter = 1;
    $prev = '';
    while (strlen($output) < $length) {
        $prev = hash_hmac('sha256', $prev . $info . chr($counter), $prk, true);
        $output .= $prev;
        $counter++;
    }
    return substr($output, 0, $length);
}

/**
 * Create VAPID JWT auth
 */
function createVapidAuth($audience) {
    $header = base64url_encode(json_encode(['typ' => 'JWT', 'alg' => 'ES256']));
    $payload = base64url_encode(json_encode([
        'aud' => $audience,
        'exp' => time() + 43200,
        'sub' => VAPID_SUBJECT,
    ]));
    
    $data = $header . '.' . $payload;
    
    // Build EC private key PEM
    $privKeyRaw = base64url_decode(VAPID_PRIVATE_KEY);
    $pubKeyRaw = base64url_decode(VAPID_PUBLIC_KEY);
    
    // Build DER for EC private key
    $der = hex2bin('30770201010420') 
         . $privKeyRaw 
         . hex2bin('a00a06082a8648ce3d030107a14403420004') 
         . $pubKeyRaw;
    
    $pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64) . "-----END EC PRIVATE KEY-----\n";
    
    $key = openssl_pkey_get_private($pem);
    if (!$key) return false;
    
    $signature = '';
    if (!openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256)) return false;
    
    // Convert DER signature to raw R||S format
    $rawSig = derToRaw($signature);
    
    return ['token' => $data . '.' . base64url_encode($rawSig)];
}

/**
 * Convert DER signature to raw R||S (64 bytes)
 */
function derToRaw($der) {
    $pos = 2;
    $rLen = ord($der[$pos + 1]);
    $r = substr($der, $pos + 2, $rLen);
    $pos = $pos + 2 + $rLen;
    $sLen = ord($der[$pos + 1]);
    $s = substr($der, $pos + 2, $sLen);
    
    // Pad/trim to 32 bytes
    $r = str_pad(ltrim($r, chr(0)), 32, chr(0), STR_PAD_LEFT);
    $s = str_pad(ltrim($s, chr(0)), 32, chr(0), STR_PAD_LEFT);
    
    return $r . $s;
}

/**
 * Base64 URL-safe encoding/decoding
 */
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64url_decode($data) {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
