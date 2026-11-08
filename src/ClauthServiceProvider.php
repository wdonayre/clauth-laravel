<?php

namespace Clauth\Laravel;

use Clauth\Laravel\Http\Controllers\ClauthController;
use Clauth\Laravel\Http\Middleware\AuthenticateWithClauthToken;
use Clauth\Laravel\Http\Middleware\KeepClauthSessionFresh;
use Clauth\Laravel\Http\Middleware\RequireClauthPermission;
use Clauth\Laravel\Socialite\ClauthProvider;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as Socialite;

class ClauthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/clauth.php', 'clauth');
        $this->app->singleton(TokenVerifier::class, fn ($app) => new TokenVerifier($app['config']['clauth']));
        $this->app->scoped(Clauth::class, fn ($app) => new Clauth($app['config']['clauth'], $app->make(TokenVerifier::class)));
    }

    public function boot(Router $router): void
    {
        $this->publishes([__DIR__.'/../config/clauth.php' => config_path('clauth.php')], 'clauth-config');
        $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'clauth-migrations');

        $router->aliasMiddleware('clauth.api', AuthenticateWithClauthToken::class);
        $router->aliasMiddleware('clauth.can', RequireClauthPermission::class);
        $router->aliasMiddleware('clauth.fresh', KeepClauthSessionFresh::class);

        $this->app->make(Socialite::class)->extend('clauth', function ($app) {
            $c = $app['config']['clauth'];
            $redirect = str_starts_with((string) $c['redirect'], 'http') ? $c['redirect'] : url($c['redirect']);

            return (new ClauthProvider($app['request'], (string) $c['client_id'], (string) ($c['client_secret'] ?? ''), $redirect))
                ->setClauth($c['issuer'], $app->make(TokenVerifier::class));
        });

        // The manifest is always served; sign-in routes only when CLAUTH_ENABLED=true.
        Route::get('/.well-known/clauth.json', [ClauthController::class, 'manifest'])->name('clauth.manifest');
        $r = config('clauth.routes');
        if (config('clauth.enabled') && ($r['enabled'] ?? true)) {
            Route::middleware($r['middleware'] ?? ['web'])->prefix($r['prefix'] ?? 'auth/clauth')->group(function () {
                Route::get('redirect', [ClauthController::class, 'redirect'])->name('clauth.redirect');
                Route::get('callback', [ClauthController::class, 'callback'])->name('clauth.callback');
                Route::match(['get', 'post'], 'logout', [ClauthController::class, 'logout'])->name('clauth.logout');
            });
        }
    }
}
