<?php

namespace Clauth\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Http;

/** Main entry point (facade `Clauth`). */
class Clauth
{
    /** @var callable|null fn (\Laravel\Socialite\Two\User $u, ClauthToken $t): ?Authenticatable */
    private $userResolver = null;

    private ?ClauthToken $current = null;

    public function __construct(private readonly array $config, private readonly TokenVerifier $verifier) {}

    public function enabled(): bool
    {
        return (bool) ($this->config['enabled'] ?? false);
    }

    public function config(?string $key = null): mixed
    {
        return $key ? data_get($this->config, $key) : $this->config;
    }

    public function verify(string $jwt, ?string $audience = null): ClauthToken
    {
        return $this->verifier->verify($jwt, $audience);
    }

    /** Claims for this request: bearer token (API) or the signed-in browser session (web). */
    public function current(): ?ClauthToken
    {
        if ($this->current) {
            return $this->current;
        }
        $request = request();
        if ($bearer = $request->bearerToken()) {
            try {
                return $this->current = $this->verify($bearer);
            } catch (InvalidTokenException) {
                return null;
            }
        }
        if ($request->hasSession() && ($claims = $request->session()->get('clauth.claims'))) {
            return $this->current = new ClauthToken($claims);
        }

        return null;
    }

    public function setCurrent(?ClauthToken $token): void
    {
        $this->current = $token;
    }

    /** Org slug for this request: X-Organization header, {org} route parameter, or the user's only org. */
    public function currentOrg(?ClauthToken $token = null): ?string
    {
        $request = request();
        $org = $request->header($this->config['org_header'] ?? 'X-Organization')
            ?: $request->route($this->config['org_route_parameter'] ?? 'org');
        if (is_object($org)) {
            $org = $org->slug ?? null;
        }

        return $org ?: ($token ?? $this->current())?->defaultOrg();
    }

    /** Exchanges a refresh token. Returns the token response, or null when Clauth refuses (revoked/disabled/no access). */
    public function refresh(string $refreshToken): ?array
    {
        $res = Http::asForm()->timeout(10)->post(rtrim($this->config['issuer'], '/').'/oauth/token', array_filter([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->config['client_id'],
            'client_secret' => $this->config['client_secret'] ?: null,
        ]));

        return $res->ok() && $res->json('access_token') ? $res->json() : null;
    }

    /** Clauth sign-out URL (ends the Clauth session too). The redirect must be registered on the client. */
    public function logoutUrl(?string $idToken = null, ?string $redirect = null): string
    {
        $redirect ??= url($this->config['routes']['after_logout'] ?? '/');

        return rtrim($this->config['issuer'], '/').'/oauth/logout?'.http_build_query(array_filter([
            'id_token_hint' => $idToken, 'client_id' => $idToken ? null : $this->config['client_id'],
            'post_logout_redirect_uri' => $redirect,
        ]));
    }

    public function resolveUsersUsing(callable $resolver): void
    {
        $this->userResolver = $resolver;
    }

    /**
     * Find the local user: by clauth_sub; on first sign-in optionally link an unlinked account with the same
     * email (never by email after linking); optionally create one.
     */
    public function resolveUser($socialiteUser, ClauthToken $token): ?Authenticatable
    {
        if ($this->userResolver) {
            return ($this->userResolver)($socialiteUser, $token);
        }
        $cfg = $this->config['users'];
        /** @var class-string<Model> $model */
        $model = $cfg['model'];
        $col = $cfg['sub_column'];
        if ($user = $model::where($col, $token->sub())->first()) {
            return $user;
        }
        if ($cfg['link_by_email'] && $token->email()
            && ($user = $model::where('email', $token->email())->whereNull($col)->first())) {
            $user->forceFill([$col => $token->sub()])->save();

            return $user;
        }
        if ($cfg['create'] && $token->email()) {
            $user = new $model;
            $user->forceFill([$col => $token->sub(), 'email' => $token->email(), 'name' => $token->name() ?? $token->email(),
                'password' => bcrypt(bin2hex(random_bytes(24)))])->save();

            return $user;
        }

        return null;
    }

    /** The manifest served at /.well-known/clauth.json. */
    public function manifest(): array
    {
        return array_merge(['app' => $this->config['audience']], $this->config['manifest'] ?? []);
    }
}
