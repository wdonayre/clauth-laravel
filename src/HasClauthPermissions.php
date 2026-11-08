<?php

namespace Clauth\Laravel;

/**
 * Add to your User model:  use \Clauth\Laravel\HasClauthPermissions;
 *   $user->clauthCan('expense.approve', 'cakesbygrace'); $user->clauthRoles('cakesbygrace');
 * Reads the current request's Clauth claims (bearer token or session), so it only answers for the signed-in user.
 */
trait HasClauthPermissions
{
    public function clauthToken(): ?ClauthToken
    {
        $t = app(Clauth::class)->current();

        return $t && $t->sub() === $this->{config('clauth.users.sub_column', 'clauth_sub')} ? $t : null;
    }

    public function clauthCan(string $permission, ?string $org = null): bool
    {
        $t = $this->clauthToken();

        return $t !== null && $t->can($permission, $org ?? app(Clauth::class)->currentOrg($t));
    }

    public function clauthRoles(?string $org = null): array
    {
        $t = $this->clauthToken();

        return $t ? $t->roles($org ?? app(Clauth::class)->currentOrg($t)) : [];
    }
}
