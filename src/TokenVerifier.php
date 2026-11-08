<?php

namespace Clauth\Laravel;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use UnexpectedValueException;

/**
 * Verifies Clauth JWTs offline: RS256 signature against the cached JWKS (refetched once on an unknown
 * `kid`, which is what happens after Clauth rotates keys), then iss, aud and exp.
 */
class TokenVerifier
{
    public function __construct(private readonly array $config) {}

    /** @throws InvalidTokenException */
    public function verify(string $jwt, ?string $audience = null, bool $checkExpiry = true): ClauthToken
    {
        $audience ??= $this->config['audience'] ?? null;
        $claims = $this->decode($jwt, false) ?? $this->decode($jwt, true);
        if ($claims === null) {
            throw new InvalidTokenException('Token signature is not valid.');
        }
        if (($claims['iss'] ?? null) !== rtrim($this->config['issuer'], '/')) {
            throw new InvalidTokenException('Token was issued by someone else.');
        }
        $aud = (array) ($claims['aud'] ?? []);
        if ($audience && ! in_array($audience, $aud, true)) {
            throw new InvalidTokenException('Token is for another app.');
        }
        if ($checkExpiry && ($claims['exp'] ?? 0) < time() - (int) ($this->config['leeway_seconds'] ?? 30)) {
            throw new InvalidTokenException('Token has expired.');
        }

        return new ClauthToken($claims, $jwt);
    }

    public function jwks(bool $fresh = false): array
    {
        $key = 'clauth.jwks.'.md5($this->config['issuer']);
        if ($fresh) {
            Cache::forget($key);
        }

        return Cache::remember($key, (int) ($this->config['jwks_cache_seconds'] ?? 3600), function () {
            $res = Http::timeout(10)->acceptJson()->get(rtrim($this->config['issuer'], '/').'/.well-known/jwks.json');
            if (! $res->ok() || empty($res->json('keys'))) {
                throw new InvalidTokenException('Could not load Clauth signing keys (HTTP '.$res->status().').');
            }

            return $res->json();
        });
    }

    private function decode(string $jwt, bool $freshKeys): ?array
    {
        try {
            JWT::$leeway = (int) ($this->config['leeway_seconds'] ?? 30);
            $keys = JWK::parseKeySet($this->jwks($freshKeys), 'RS256');
            // exp is checked by JWT::decode too; we re-check above so revoked-but-unexpired logic stays in one place.
            $payload = JWT::decode($jwt, $keys);

            return json_decode(json_encode($payload), true);
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new InvalidTokenException('Token has expired.', previous: $e);
        } catch (UnexpectedValueException|\DomainException|\InvalidArgumentException) {
            return null; // unknown kid / bad signature → caller retries once with fresh keys
        }
    }
}
