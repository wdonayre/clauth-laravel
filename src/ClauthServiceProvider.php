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

        // The bar's organization menu writes a plain cookie; let it through unencrypted.
        \Illuminate\Cookie\Middleware\EncryptCookies::except(['clauth_org']);

        // @clauthBar — the required Clauth top bar. Renders only for people signed in through Clauth.
        // @clauthSignInLabel — "Continue with CakesbyGrace Account" (or "Sign in with Clauth"), from Clauth's brand for this app.
        \Illuminate\Support\Facades\Blade::directive('clauthSignInLabel', fn () => "<?php echo e(app(\\Clauth\\Laravel\\Clauth::class)->signInLabel()); ?>");
        \Illuminate\Support\Facades\Blade::directive('clauthBar', fn ($org = null) => "<?php echo app(\\Clauth\\Laravel\\Clauth::class)->barHtml({$org}); ?>");

        $router->aliasMiddleware('clauth.api', AuthenticateWithClauthToken::class);
        $router->aliasMiddleware('clauth.can', RequireClauthPermission::class);
        $router->aliasMiddleware('clauth.fresh', KeepClauthSessionFresh::class);

        $this->app->make(Socialite::class)->extend('clauth', function ($app) {
            $c = $app['config']['clauth'];
            $redirect = str_starts_with((string) $c['redirect'], 'http') ? $c['redirect'] : url($c['redirect']);

            return (new ClauthProvider($app['request'], (string) $c['client_id'], (string) ($c['client_secret'] ?? ''), $redirect))
                ->setClauth($c['issuer'], $app->make(TokenVerifier::class), $c['login_url'] ?? null);
        });

        // Webhook receiver (no session/CSRF; the signature is the check) when a secret is set.
        if (config('clauth.webhooks.secret')) {
            Route::post(config('clauth.webhooks.path', 'clauth/webhook'), \Clauth\Laravel\Http\Controllers\WebhookController::class)
                ->middleware('throttle:600,1')->name('clauth.webhook');
        }

        // The manifest is always served; sign-in routes only when CLAUTH_ENABLED=true.
        Route::get('/.well-known/clauth.json', [ClauthController::class, 'manifest'])->name('clauth.manifest');
        $r = config('clauth.routes');
        if (config('clauth.enabled') && ($r['enabled'] ?? true)) {
            Route::middleware($r['middleware'] ?? ['web'])->prefix($r['prefix'] ?? 'auth/clauth')->group(function () {
                Route::get('redirect', [ClauthController::class, 'redirect'])->name('clauth.redirect');
                Route::get('callback', [ClauthController::class, 'callback'])->name('clauth.callback');
                Route::match(['get', 'post'], 'logout', [ClauthController::class, 'logout'])->name('clauth.logout');
                Route::get('bar', [ClauthController::class, 'bar'])->name('clauth.bar');
                Route::post('bar/read', [ClauthController::class, 'barRead'])->name('clauth.bar.read');
            });
        }
    }
}
