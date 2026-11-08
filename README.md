# clauth-laravel

Sign in to a Laravel app with **Clauth** (https://auth.thecakelabs.com). One package per app gives you:

- a Socialite driver `clauth` (Authorization Code + PKCE + nonce, which Clauth requires);
- ready routes `/auth/clauth/redirect`, `/auth/clauth/callback`, `/auth/clauth/logout`;
- offline token checks against Clauth's public keys (JWKS cached 1 h, refetched when Clauth rotates keys);
- per-organization permission checks: middleware `clauth.can:…`, `$user->clauthCan(…)`;
- `clauth.fresh`, which refreshes the session token so role changes land within 15 min and disabled users get signed out;
- `clauth.api` for bearer-token APIs (mobile apps, SPAs, other servers);
- your permissions manifest at `/.well-known/clauth.json`, built from `config/clauth.php`.

The rule (SPEC §4): **the app defines permissions and enforces them; Clauth decides who has which role in which
organization.** Data rules (own team, ₱ limits, "only my store") stay in the app.

Tested 2026-11-08 against local Clauth with a fresh Laravel 12 app: sign-in, linking by email, `clauth.can` 200/403,
role change applied after refresh, disabled user signed out, `clauth.api` 401/200, manifest route.

---

## Connecting an app (Laravel web app)

### 1. In Clauth (Admin › Apps)

1. **Register app** → key = the app's short name (e.g. `xpenses`). This becomes the token audience and can't change.
   Type **Web app**; redirect URL `https://<app>/auth/clauth/callback`; tick the organizations that use it.
2. Copy the **client secret** shown once.
3. **Settings tab** → add `https://<app>/` (or your sign-out landing page) under *After sign-out URLs*.
4. **Sign-in page tab** → logo, style and accent color.

### 2. In the app

```bash
composer require wdonayre/clauth-laravel        # see "Installing the package" below
php artisan vendor:publish --tag=clauth-config
php artisan vendor:publish --tag=clauth-migrations && php artisan migrate   # adds users.clauth_sub
```

`.env`:

```dotenv
CLAUTH_ENABLED=false            # flip to true when ready — the kit does nothing to sign-in until then
CLAUTH_ISSUER=https://auth.thecakelabs.com
CLAUTH_AUDIENCE=xpenses
CLAUTH_CLIENT_ID=…
CLAUTH_CLIENT_SECRET=…
CLAUTH_REDIRECT_URI=https://expenses.thecakelabs.com/auth/clauth/callback
```

User model:

```php
use Clauth\Laravel\HasClauthPermissions;

class User extends Authenticatable
{
    use HasClauthPermissions;   // $user->clauthCan('expense.approve'), $user->clauthRoles()
}
```

### 3. Declare permissions (`config/clauth.php` → `manifest`)

```php
'manifest' => [
    'version' => 1,
    'permissions' => [
        ['key' => 'expense.submit',  'description' => 'Create and submit expense claims'],
        ['key' => 'expense.approve', 'description' => 'Approve or reject claims'],
    ],
    'roles' => [
        ['key' => 'owner',  'name' => 'Owner',  'permissions' => ['*']],
        ['key' => 'member', 'name' => 'Member', 'permissions' => ['expense.submit']],
    ],
],
```

Deploy, then in Clauth set the app's **Manifest URL** to `https://<app>/.well-known/clauth.json` and press
**Sync now** (it also syncs nightly). Roles an admin edits in Clauth are never overwritten by a sync.

### 4. Use it

```php
// routes/web.php
Route::get('/login', fn () => redirect()->route('clauth.redirect'))->name('login');   // replaces the app's own login

Route::middleware(['auth', 'clauth.fresh'])->group(function () {
    Route::post('/expenses/{expense}/approve', ApproveController::class)->middleware('clauth.can:expense.approve');
});
```

```php
// anywhere
if (auth()->user()->clauthCan('report.export')) { … }
$org = Clauth::currentOrg();          // X-Organization header, {org} route parameter, or the user's only org
Clauth::current()?->roles($org);      // ['finance']
```

Sign-out link: `route('clauth.logout')`. It ends the app session and the Clauth session.

**Organizations.** Permissions are per organization (`orgs` claim keyed by slug, e.g. `cakesbygrace`). Requests
say which org they're about via the `X-Organization` header or an `{org}` route parameter (configurable). Someone
in a single org doesn't need either.

### 5. Switch over

1. Ship with `CLAUTH_ENABLED=false`, then register the app and sync the manifest.
2. Give people access in Clauth (invite, or for existing users: add them to the org and pick a role).
3. Set `CLAUTH_ENABLED=true`. On first Clauth sign-in, an existing local account with the **same email** is
   linked by `clauth_sub`. After that, linking is by `sub` only, so email changes don't break it.
4. When everyone has signed in through Clauth, remove the app's own password login.

Want local users created automatically on first sign-in? Set `users.create => true`, or take full control:

```php
// AppServiceProvider::boot()
Clauth::resolveUsersUsing(function (\Clauth\Laravel\Socialite\ClauthUser $su, \Clauth\Laravel\ClauthToken $t) {
    return \App\Models\User::firstWhere('clauth_sub', $t->sub());   // return null to refuse
});
```

---

## APIs, mobile apps and SPAs

Protect API routes with `clauth.api`. It checks the `Authorization: Bearer <access token>` offline and signs in the
linked local user for that request:

```php
Route::middleware('clauth.api')->group(function () {
    Route::get('/me', fn () => auth()->user());
    Route::post('/expenses/{id}/approve', …)->middleware('clauth.can:expense.approve');
});
```

- **Expo / React Native:** register a second client on the same app in Clauth, type **Mobile app or SPA** (no
  secret), redirect `xpenses://auth/callback`. Use `expo-auth-session` with PKCE and discovery
  `https://auth.thecakelabs.com`, scopes `openid profile email clauth offline_access`. Keep tokens in
  `expo-secure-store` and send the access token as the bearer.
- **Server-to-server:** a client of type *Server-to-server* uses client credentials. Its tokens have no user
  (`sub` = `client_…`); use `clauth.api:optional-user`.

Access tokens last 15 minutes and refresh tokens 30 days. Refresh tokens rotate: reusing an old refresh token signs
that person out of the app everywhere.

---

## Installing the package

Private repo **wdonayre/clauth-laravel** (releases are `v*` tags). In each app:

```bash
composer config repositories.clauth vcs git@github.com:wdonayre/clauth-laravel.git
composer require wdonayre/clauth-laravel:^0.1
```

The app's production server must be able to read this repo: add the server's deploy public key to
**wdonayre/clauth-laravel › Settings › Deploy keys** (read-only). GitHub doesn't allow one deploy key on two
repos, so use a separate key for each repo and an SSH host alias (or an auth.json token) on the server.

To work on the kit locally against an app, use a path repository instead:
`composer config repositories.clauth path "/path/to/Clauth/_skills/clauth-laravel"` + `composer require wdonayre/clauth-laravel:@dev`.

Releasing a kit change: commit, `git tag v0.1.1 && git push origin main v0.1.1`, then `composer update wdonayre/clauth-laravel` in each app.

## Non-Laravel apps

Any OIDC client library works. Discovery is at `https://auth.thecakelabs.com/.well-known/openid-configuration`,
PKCE (S256) is required, and the access token's `orgs` claim holds roles and permissions per organization. The
plain-PHP sample in the Clauth repo (`tools/demo-client/`) shows the whole flow, including offline JWT checks, in about 80 lines.
