<?php

namespace Clauth\Laravel\Http\Middleware;

use Clauth\Laravel\Clauth;
use Closure;
use Illuminate\Http\Request;

/**
 * `clauth.can:expense.approve` (any of several: `clauth.can:expense.approve,report.export`).
 * Checks the permission in the request's organization (X-Organization header / {org} / only org).
 * 403 when signed in without it; 401 when there are no Clauth claims at all.
 */
class RequireClauthPermission
{
    public function __construct(private readonly Clauth $clauth) {}

    public function handle(Request $request, Closure $next, string ...$permissions)
    {
        $token = $this->clauth->current();
        if (! $token) {
            return $request->expectsJson() ? response()->json(['error' => 'unauthenticated'], 401) : redirect()->guest(route('clauth.redirect'));
        }
        $org = $this->clauth->currentOrg($token);
        if (! $org || ! $token->inOrg($org)) {
            abort(403, 'Choose an organization you belong to.');
        }
        foreach ($permissions as $p) {
            if ($token->can($p, $org)) {
                return $next($request);
            }
        }
        abort(403, 'You don’t have permission to do that here.');
    }
}
