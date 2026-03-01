<?php
/**
 * ESPE BASKET U9 — Web Push via minishlink/web-push (lib standard PHP)
 * Utilise la bibliothèque minishlink/web-push pour un envoi fiable.
 */

if (!defined('VAPID_PUBLIC_KEY'))  define('VAPID_PUBLIC_KEY',  'BKux74q_3ayYXtGDcNlZUN0qwZMkcPX93qxNY9hpngeH2Mpk-oLytRRfzIfyy2V8TM1cmc9CyrqNmGrtgvHtVuA');
if (!defined('VAPID_PRIVATE_KEY')) define('VAPID_PRIVATE_KEY', 'ZKFkKhcGwueezbCjZNAmnyyC_Xx326CO52xHkAVbQbU');
if (!defined('VAPID_SUBJECT'))    define('VAPID_SUBJECT',     'https://espeu9.fr');

$__web_push_autoloaded = false;

function web_push_ensure_autoload() {
    global $__web_push_autoloaded;
    if ($__web_push_autoloaded) return true;
    $autoload = __DIR__ . '/vendor/autoload.php';
    if (!is_file($autoload)) {
        return false;
    }
    require_once $autoload;
    $__web_push_autoloaded = true;
    return true;
}

/**
 * Envoie une notification push à un abonné.
 * Signature inchangée pour compatibilité avec api.php.
 *
 * @param array $subscription ['endpoint' => string, 'keys' => ['p256dh' => string, 'auth' => string]]
 * @param array|string $payload ['title'=>..., 'body'=>..., 'icon'=>..., 'badge'=>..., 'data'=>['url'=>...]] ou JSON string
 * @return array ['success' => bool, 'code' => int, 'error' => string?, 'response' => string?]
 */
function sendWebPush($subscription, $payload) {
    if (!web_push_ensure_autoload()) {
        return ['success' => false, 'error' => 'Composer vendor non installé (exécuter: composer install)', 'code' => 0];
    }

    try {
        $endpoint = $subscription['endpoint'] ?? '';
        $keys = $subscription['keys'] ?? [];
        $p256dh = $keys['p256dh'] ?? '';
        $auth   = $keys['auth'] ?? '';

        if (!$endpoint || !$p256dh || !$auth) {
            return ['success' => false, 'error' => 'Données d’abonnement incomplètes', 'code' => 0];
        }

        $payloadJson = is_string($payload) ? $payload : json_encode($payload, JSON_UNESCAPED_UNICODE);

        $authConfig = [
            'VAPID' => [
                'subject'    => VAPID_SUBJECT,
                'publicKey'  => VAPID_PUBLIC_KEY,
                'privateKey' => VAPID_PRIVATE_KEY,
            ],
        ];

        $sub = \Minishlink\WebPush\Subscription::create([
            'endpoint' => $endpoint,
            'keys' => [
                'p256dh' => $p256dh,
                'auth'   => $auth,
            ],
        ]);

        $webPush = new \Minishlink\WebPush\WebPush($authConfig);
        $report  = $webPush->sendOneNotification($sub, $payloadJson);

        if ($report->isSuccess()) {
            return ['success' => true, 'code' => 200, 'response' => ''];
        }

        $reason = $report->getReason();
        $request = method_exists($report, 'getRequest') ? $report->getRequest() : null;
        $code = 0;
        if ($request && method_exists($request, 'getStatusCode')) {
            $code = $request->getStatusCode();
        }
        if (!$code && $reason && preg_match('/\b(\d{3})\b/', $reason, $m)) {
            $code = (int) $m[1];
        }

        return [
            'success'  => false,
            'code'     => $code,
            'error'    => $reason ?: 'Échec envoi',
            'response' => $reason,
        ];
    } catch (\Throwable $e) {
        return [
            'success' => false,
            'code'    => 0,
            'error'   => $e->getMessage(),
            'response' => $e->getMessage(),
        ];
    }
}

// Aliases pour push-debug.php si besoin
function getPushLog() { return []; }
function pushLog($msg) {}
