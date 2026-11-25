<?php

namespace Clauth\Laravel\Http\Controllers;

use Clauth\Laravel\Events\WebhookReceived;
use Clauth\Laravel\Webhooks\UserSync;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;

/**
 * POST /clauth/webhook — checks Clauth-Signature (t=…,v1=HMAC-SHA256(secret, "t.body")), rejects stale or
 * replayed deliveries, ignores events older than the newest one already seen for that person, then syncs the
 * local user (unless turned off) and fires WebhookReceived.
 */
class WebhookController
{
    public function __invoke(Request $request)
    {
        $cfg = config('clauth');
        $secret = (string) ($cfg['webhooks']['secret'] ?? '');
        $body = $request->getContent();
        parse_str(str_replace(',', '&', (string) $request->header('Clauth-Signature')), $sig);
        $t = (int) ($sig['t'] ?? 0);
        if ($secret === '' || ! isset($sig['v1']) || ! hash_equals(hash_hmac('sha256', $t.'.'.$body, $secret), (string) $sig['v1'])) {
            return response()->json(['error' => 'bad signature'], 401);
        }
        if (abs(time() - $t) > (int) ($cfg['webhooks']['tolerance_seconds'] ?? 300)) {
            return response()->json(['error' => 'stale'], 401);
        }
        $payload = json_decode($body, true);
        if (! is_array($payload) || empty($payload['type'])) {
            return response()->json(['error' => 'bad body'], 400);
        }
        $delivery = (string) $request->header('Clauth-Delivery', $payload['id'] ?? '');
        if ($delivery !== '' && ! Cache::add('clauth:webhook:'.$delivery, 1, now()->addDays(2))) {
            return response()->json(['ok' => true, 'duplicate' => true]);
        }
        $type = $payload['type'];
        $data = $payload['data'] ?? [];

        // Out-of-order guard: per person, an event older than one already handled is skipped.
        $sub = $data['user']['id'] ?? null;
        $seq = (int) ($payload['sequence'] ?? 0);
        if ($sub && $seq) {
            $key = 'clauth:webhook:seq:'.$sub;
            if ($seq < (int) Cache::get($key, 0)) {
                return response()->json(['ok' => true, 'stale_sequence' => true]);
            }
            Cache::forever($key, $seq);
        }

        $user = null;
        if ($type !== 'ping' && ($cfg['webhooks']['manage_users'] ?? true)) {
            $user = app()->makeWith(UserSync::class, ['config' => $cfg])->handle($type, $data);
        }
        Event::dispatch(new WebhookReceived($type, $data, $payload, $user));

        return response()->json(['ok' => true]);
    }
}
