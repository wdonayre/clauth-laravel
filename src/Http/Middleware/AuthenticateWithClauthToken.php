<?php

namespace Clauth\Laravel\Http\Middleware;

use Clauth\Laravel\Clauth;
use Clauth\Laravel\InvalidTokenException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * API routes (`clauth.api`): require a valid Clauth access token (offline check) and sign in the linked
 * local user for this request. 401 otherwise. Use `clauth.api:optional-user` to allow tokens with no local user.
 */
class AuthenticateWithClauthToken
{
    public function __construct(private readonly Clauth $clauth) {}

    public function handle(Request $request, Closure $next, ?string $mode = null)
    {
        $jwt = $request->bearerToken();
        if (! $jwt) {
            return $this->deny('missing_token');
        }
        try {
            $token = $this->clauth->verify($jwt);
        } catch (InvalidTokenException $e) {
            return $this->deny('invalid_token', $e->getMessage());
        }
        $this->clauth->setCurrent($token);
        $request->attributes->set('clauth', $token);

        if ($token->isUser()) {
            $model = config('clauth.users.model');
            $user = $model::where(config('clauth.users.sub_column'), $token->sub())->first();
            if (! $user && $mode !== 'optional-user') {
                return $this->deny('unknown_user', 'No local account is linked to this Clauth user yet.');
            }
            if ($user) {
                Auth::setUser($user);
            }
        }

        return $next($request);
    }

    private function deny(string $code, string $msg = 'Sign in with Clauth.')
    {
        return response()->json(['error' => $code, 'message' => $msg], 401, ['WWW-Authenticate' => 'Bearer error="'.$code.'"']);
    }
}
