<?php

declare(strict_types=1);

namespace Polaris\Laravel\Console;

use Illuminate\Console\Command;

use function basename;
use function date;
use function file_get_contents;
use function file_put_contents;
use function glob;

/**
 * `php artisan polaris:install`: publishes config/polaris.php and writes the migration that creates
 * the Polaris tables (then `php artisan migrate`).
 */
final class InstallCommand extends Command
{
    protected $signature = 'polaris:install {--force : Overwrite a published config/polaris.php}';
    protected $description = 'Publishes config/polaris.php and writes the migration that creates the Polaris tables';

    public function handle(): int
    {
        $this->call('vendor:publish', ['--tag' => 'polaris-config', '--force' => (bool) $this->option('force')]);
        $directory = $this->laravel->databasePath('migrations');
        $existing = glob($directory . '/*_create_polaris_tables.php') ?: [];
        if ($existing !== []) {
            $this->components->info('Migration already present: ' . basename($existing[0]));

            return self::SUCCESS;
        }
        $file = $directory . '/' . date('Y_m_d_His') . '_create_polaris_tables.php';
        file_put_contents($file, (string) file_get_contents(__DIR__ . '/../../stubs/migration.stub'));
        $this->components->info('Created ' . basename($file) . '; run php artisan migrate');

        return self::SUCCESS;
    }
}
