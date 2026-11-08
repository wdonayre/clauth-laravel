<?php

namespace Clauth\Laravel\Http\Controllers;

use Clauth\Laravel\Clauth;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Socialite\Facades\Socialite;

/** Built-in /auth/clauth/{redirect,callback,logout} and /.well-known/clauth.json. */
class ClauthController
{
    public function __construct(private readonly Clauth $clauth) {}

    public function redirect()
    {
        return Socialite::driver('clauth')->scopes($this->clauth->config('scopes'))->redirect();
    }

    public function callback(Request $request)
    {
        if ($request->has('error')) {
            $msg = $request->input('error') === 'access_denied'
                ? 'Your Clauth account doesn’t have access to this app. Ask your admin.'
                : 'Sign-in didn’t finish ('.$request->input('error').'). Please try again.';

            return $this->failed($msg);
        }
        try {
            $su = Socialite::driver('clauth')->user();
        } catch (\Throwable $e) {
            report($e);

            return $this->failed('Sign-in didn’t finish. Please try again.');
        }
        $token = $this->clauth->verify($su->token);
        $user = $this->clauth->resolveUser($su, $token);
        if (! $user) {
            return $this->failed('Your Clauth account isn’t linked to an account in this app yet. Ask your admin.');
        }

        Auth::guard($this->clauth->config('users.guard'))->login($user);
        $request->session()->regenerate();
        $request->session()->put([
            'clauth.claims' => $token->claims,
            'clauth.access_token' => $su->token,
            'clauth.refresh_token' => $su->refreshToken,
            'clauth.expires_at' => $token->expiresAt(),
            'clauth.id_token' => $su->idToken ?? null,
        ]);

        return redirect()->intended($this->clauth->config('routes.home') ?? '/');
    }

    public function logout(Request $request)
    {
        $idToken = $request->session()->get('clauth.id_token');
        Auth::guard($this->clauth->config('users.guard'))->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->away($this->clauth->logoutUrl($idToken));
    }

    /** JSON for the Clauth bar (same-origin, so the browser never holds a Clauth token). */
    public function bar(Request $request)
    {
        if (! Auth::guard($this->clauth->config('users.guard'))->check() || ! $request->session()->has('clauth.access_token')) {
            return response()->json(['error' => 'unauthenticated'], 401);
        }
        if (! $this->clauth->refreshSession($request) || ! ($data = $this->clauth->barData($request))) {
            return response()->json(['error' => 'session_ended'], 401);
        }

        return response()->json($data)->header('Cache-Control', 'private, no-store');
    }

    public function manifest()
    {
        return response()->json($this->clauth->manifest())->header('Cache-Control', 'public, max-age=300');
    }

    private function failed(string $message)
    {
        return response($message, 403)->header('Content-Type', 'text/plain; charset=utf-8');
    }
}
