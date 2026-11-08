<?php

namespace Clauth\Laravel\Socialite;

use Laravel\Socialite\Two\User;

class ClauthUser extends User
{
    /** Raw ID token (for sign-out with id_token_hint). */
    public ?string $idToken = null;

    /** Verified access-token claims, including `orgs`. */
    public array $clauth = [];
}
