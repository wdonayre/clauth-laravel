<?php

namespace Clauth\Laravel\Http\Middleware;

use Clauth\Laravel\Clauth;
use Clauth\Laravel\InvalidTokenException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * Web routes (`clauth.fresh`): when the stored access token is about to expire, refresh it, so role changes
 * reach the app within 15 minutes and disabled/removed users are signed out. Put it after `auth`.
 */
class KeepClauthSessionFresh
{
    public function __construct(private readonly Clauth $clauth) {}

    public function handle(Request $request, Closure $next)
    {
        $s = $request->session();
        $exp = (int) $s->get('clauth.expires_at', 0);
        if ($s->has('clauth.refresh_token') && $exp < time() + 60) {
            $res = $this->clauth->refresh($s->get('clauth.refresh_token'));
            try {
                $token = $res ? $this->clauth->verify($res['access_token']) : null;
            } catch (InvalidTokenException) {
                $token = null;
            }
            if (! $token) {
                Auth::guard(config('clauth.users.guard'))->logout();
                $s->invalidate();
                $s->regenerateToken();

                return $request->expectsJson() ? response()->json(['error' => 'session_ended'], 401) : redirect()->guest(route('clauth.redirect'));
            }
            $s->put([
                'clauth.claims' => $token->claims, 'clauth.access_token' => $res['access_token'], 'clauth.expires_at' => $token->expiresAt(),
                'clauth.refresh_token' => $res['refresh_token'] ?? $s->get('clauth.refresh_token'),
                'clauth.id_token' => $res['id_token'] ?? $s->get('clauth.id_token'),
            ]);
            $this->clauth->setCurrent($token);
        }

        return $next($request);
    }
}
