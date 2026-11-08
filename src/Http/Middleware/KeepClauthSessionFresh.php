<?php

namespace Clauth\Laravel\Http\Middleware;

use Clauth\Laravel\Clauth;
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
        if (! $this->clauth->refreshSession($request)) {
            Auth::guard(config('clauth.users.guard'))->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return $request->expectsJson() ? response()->json(['error' => 'session_ended'], 401) : redirect()->guest(route('clauth.redirect'));
        }

        return $next($request);
    }
}
