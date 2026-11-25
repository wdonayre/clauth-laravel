<?php

namespace Clauth\Laravel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Clauth\Laravel\ClauthToken verify(string $jwt, ?string $audience = null)
 * @method static \Clauth\Laravel\ClauthToken|null current()
 * @method static array|null refresh(string $refreshToken)
 * @method static string logoutUrl(?string $idToken = null, ?string $redirect = null)
 * @method static void resolveUsersUsing(callable $resolver)
 * @method static void onWebhook(string $type, callable $handler)
 * @method static array brand()
 * @method static string signInLabel()
 * @method static bool enabled()
 */
class Clauth extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Clauth\Laravel\Clauth::class;
    }
}
