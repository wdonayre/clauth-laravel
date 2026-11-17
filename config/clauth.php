<?php

return [
    // Connection (Clauth › Apps › your app › Integration shows these values)
    'issuer' => env('CLAUTH_ISSUER', 'https://auth.cebos.tech'),
    // Optional: the app's own Clauth sign-in domain (Clauth › Apps › Sign-in page › Custom domain), e.g.
    // https://auth.cebpos.com. Only sign-in/sign-out pages move there; tokens keep the issuer above.
    'login_url' => env('CLAUTH_LOGIN_URL'),
    'client_id' => env('CLAUTH_CLIENT_ID'),
    'client_secret' => env('CLAUTH_CLIENT_SECRET'),
    'redirect' => env('CLAUTH_REDIRECT_URI', '/auth/clauth/callback'),
    'audience' => env('CLAUTH_AUDIENCE'),               // your app key in Clauth, e.g. "xpenses"
    'scopes' => ['openid', 'profile', 'email', 'clauth', 'offline_access'],

    // Off by default so installing the kit changes nothing until you switch it on.
    'enabled' => (bool) env('CLAUTH_ENABLED', false),

    // Built-in routes: /auth/clauth/redirect, /auth/clauth/callback, /auth/clauth/logout and /.well-known/clauth.json
    'routes' => [
        'enabled' => true,
        'prefix' => 'auth/clauth',
        'middleware' => ['web'],
        'home' => '/',                        // where to go after sign-in when there's no intended URL
        'after_logout' => '/',                // must be listed in the client's "After sign-out URLs" in Clauth
    ],

    // The Clauth bar (required in every connected app): put @clauthBar at the top of the staff layout's <body>.
    // Your CSP must allow script-src https://auth.cebos.tech (and img-src for app icons).
    'bar' => [
        'enabled' => true,
    ],

    // Local user linking: by `sub` (users.clauth_sub). First sign-in may link an existing account by email.
    'users' => [
        'model' => env('CLAUTH_USER_MODEL', 'App\\Models\\User'),
        'sub_column' => 'clauth_sub',
        'link_by_email' => true,
        'create' => false,                     // true: create a local user on first sign-in
        'guard' => null,                       // auth guard for web sign-in (null = default)
    ],

    // Which organization a request is about (Xpenses-style header), for `clauth.can` checks.
    'org_header' => 'X-Organization',
    'org_route_parameter' => 'org',

    'jwks_cache_seconds' => 3600,
    'leeway_seconds' => 30,

    // Your permissions manifest, served at /.well-known/clauth.json (SPEC §7). Keep it in code, review in PRs.
    'manifest' => [
        'version' => 1,
        'permissions' => [
            // ['key' => 'expense.submit', 'description' => 'Create and submit expense claims'],
        ],
        'roles' => [
            // ['key' => 'owner', 'name' => 'Owner', 'permissions' => ['*']],
            // ['key' => 'member', 'name' => 'Member', 'permissions' => ['expense.submit']],
        ],
    ],
];
