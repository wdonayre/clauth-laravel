<?php

namespace Clauth\Laravel\Webhooks;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;

/**
 * Default webhook handling (config clauth.webhooks.manage_users): keeps the local user row in step with Clauth.
 *  - access.granted / access.changed / invite.accepted: find by sub, else link an unlinked account by email
 *    (once, like sign-in), else create it; mark active.
 *  - access.removed with no access left in any organization (still_in empty): mark inactive.
 *  - user.updated: name and email. user.disabled / user.enabled: inactive / active.
 * "Active" is the clauth.webhooks.active_column (default clauth_active) when the users table has it.
 */
class UserSync
{
    public function __construct(private readonly array $config) {}

    public function handle(string $type, array $data): mixed
    {
        $person = $data['user'] ?? null;
        if (! $person || empty($person['id'])) {
            return null;
        }
        $user = $this->find($person);

        switch ($type) {
            case 'access.granted':
            case 'access.changed':
            case 'invite.accepted':
                $user ??= $this->create($person);
                $this->setActive($user, ($person['status'] ?? 'active') !== 'disabled');
                break;
            case 'access.removed':
                if ($user && empty($data['still_in'])) {
                    $this->setActive($user, false);
                }
                break;
            case 'user.updated':
                if ($user) {
                    $user->forceFill(array_filter(['name' => $person['name'] ?? null, 'email' => $person['email'] ?? null]))->save();
                }
                break;
            case 'user.disabled':
                $user && $this->setActive($user, false);
                break;
            case 'user.enabled':
                $user && $this->setActive($user, true);
                break;
        }

        return $user;
    }

    private function model(): string
    {
        return $this->config['users']['model'];
    }

    private function col(): string
    {
        return $this->config['users']['sub_column'];
    }

    public function find(array $person): ?Model
    {
        $model = $this->model();
        if ($user = $model::where($this->col(), $person['id'])->first()) {
            return $user;
        }
        if (($this->config['users']['link_by_email'] ?? true) && ! empty($person['email'])
            && ($user = $model::where('email', $person['email'])->whereNull($this->col())->first())) {
            $user->forceFill([$this->col() => $person['id']])->save();

            return $user;
        }

        return null;
    }

    private function create(array $person): ?Model
    {
        if (empty($person['email']) || ! ($this->config['webhooks']['create_users'] ?? true)) {
            return null;
        }
        $model = $this->model();
        $user = new $model;
        $user->forceFill([$this->col() => $person['id'], 'email' => $person['email'], 'name' => $person['name'] ?? $person['email'],
            'password' => bcrypt(bin2hex(random_bytes(24)))])->save();

        return $user;
    }

    private function setActive(?Model $user, bool $on): void
    {
        $col = $this->config['webhooks']['active_column'] ?? 'clauth_active';
        if ($user && $col && Schema::hasColumn($user->getTable(), $col) && (bool) $user->getAttribute($col) !== $on) {
            $user->forceFill([$col => $on])->save();
        }
    }
}
