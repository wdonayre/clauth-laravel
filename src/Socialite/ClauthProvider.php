<?php

namespace Clauth\Laravel\Socialite;

use Clauth\Laravel\TokenVerifier;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Socialite\Two\AbstractProvider;

/**
 * Socialite driver "clauth": Authorization Code + PKCE (required by Clauth), nonce, and the access
 * token verified OFFLINE against JWKS — no userinfo round-trip. The user's `orgs` claim is in ->clauth.
 */
class ClauthProvider extends AbstractProvider
{
    protected $usesPKCE = true;

    protected $scopeSeparator = ' ';

    protected string $issuer;

    protected TokenVerifier $verifier;

    public function setClauth(string $issuer, TokenVerifier $verifier): static
    {
        $this->issuer = rtrim($issuer, '/');
        $this->verifier = $verifier;

        return $this;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->issuer.'/oauth/authorize', $state);
    }

    protected function getCodeFields($state = null): array
    {
        $fields = parent::getCodeFields($state);
        if ($this->request->hasSession()) {
            $nonce = Str::random(32);
            $this->request->session()->put('clauth.nonce', $nonce);
            $fields['nonce'] = $nonce;
        }

        return $fields;
    }

    protected function getTokenUrl(): string
    {
        return $this->issuer.'/oauth/token';
    }

    protected function getUserByToken($token): array
    {
        return $this->verifier->verify($token)->claims;
    }

    protected function mapUserToObject(array $user): ClauthUser
    {
        return (new ClauthUser)->setRaw($user)->map([
            'id' => $user['sub'],
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'clauth' => $user,
        ]);
    }

    protected function userInstance(array $response, array $user)
    {
        return parent::userInstance($response, $user)->map(['idToken' => Arr::get($response, 'id_token')]);
    }

    /** Checks the ID token's nonce, then returns the user with tokens attached (->idToken, ->clauth). */
    public function user()
    {
        $user = parent::user();
        $idToken = $user->idToken ?? null;
        if ($idToken && $this->request->hasSession()) {
            $id = $this->verifier->verify($idToken, $this->clientId);
            $expected = $this->request->session()->pull('clauth.nonce');
            if ($expected && ($id->claims['nonce'] ?? null) !== $expected) {
                throw new \Clauth\Laravel\InvalidTokenException('Sign-in response nonce does not match.');
            }
        }

        return $user;
    }
}
