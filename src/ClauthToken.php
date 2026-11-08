<?php

namespace Clauth\Laravel;

/**
 * Verified Clauth access-token claims. Roles/permissions are per organization (SPEC §6.2):
 *   $t->can('expense.approve', 'cakesbygrace'); $t->roles('cakesbygrace'); $t->orgs();
 */
class ClauthToken
{
    public function __construct(public readonly array $claims, public readonly string $raw = '') {}

    public function sub(): string
    {
        return (string) ($this->claims['sub'] ?? '');
    }

    public function email(): ?string
    {
        return $this->claims['email'] ?? null;
    }

    public function name(): ?string
    {
        return $this->claims['name'] ?? null;
    }

    public function isUser(): bool
    {
        return str_starts_with($this->sub(), 'usr_');
    }

    public function scopes(): array
    {
        return array_values(array_filter(explode(' ', (string) ($this->claims['scope'] ?? ''))));
    }

    public function expiresAt(): int
    {
        return (int) ($this->claims['exp'] ?? 0);
    }

    /** Org slugs this person can use the app in. */
    public function orgs(): array
    {
        return array_keys($this->claims['orgs'] ?? []);
    }

    public function roles(?string $org = null): array
    {
        $org ??= $this->defaultOrg();

        return $org ? array_values($this->claims['orgs'][$org]['roles'] ?? []) : [];
    }

    public function permissions(?string $org = null): array
    {
        $org ??= $this->defaultOrg();

        return $org ? array_values($this->claims['orgs'][$org]['permissions'] ?? []) : [];
    }

    public function hasRole(string $role, ?string $org = null): bool
    {
        return in_array($role, $this->roles($org), true);
    }

    public function can(string $permission, ?string $org = null): bool
    {
        return in_array($permission, $this->permissions($org), true);
    }

    public function inOrg(string $org): bool
    {
        return isset($this->claims['orgs'][$org]);
    }

    /** The only org, when the person has exactly one. */
    public function defaultOrg(): ?string
    {
        $orgs = $this->orgs();

        return count($orgs) === 1 ? $orgs[0] : null;
    }
}
