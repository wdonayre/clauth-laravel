<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

// Set by Clauth webhooks: false once someone has no access to the app left, or their Clauth account is off.
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasColumn('users', 'clauth_active')) {
            Schema::table('users', fn (Blueprint $t) => $t->boolean('clauth_active')->default(true));
        }
    }

    public function down(): void
    {
        if (Schema::hasColumn('users', 'clauth_active')) {
            Schema::table('users', fn (Blueprint $t) => $t->dropColumn('clauth_active'));
        }
    }
};
