# Plugins

A plugin is a Composer package that extends Polaris from the outside: its own tables, endpoints, services,
listeners and permissions, declared as data and wired by `Polaris::create()`. Core's contract does not
change because a plugin is present; a plugin owns only the tables it declares and the routes its manifest
directory holds. The contract is `Polaris\Contract\Plugin`; `Polaris\Plugin\AbstractPlugin` gives every
optional part an empty default.

```php
final class AuditPlugin extends AbstractPlugin
{
    public function id(): string { return 'audit'; }
    public function schema(): array { return [AuditEventSchema::define()]; }               // Polaris\Schema\Model list
    public static function manifestDirectory(): string { return __DIR__ . '/../api'; }    // api/audit/**/*.yaml
    public function services(): array { return [AuditQuery::class => fn (Graph $g) => new AuditQuery($g->database())]; }
    public function listeners(Graph $graph): array { return [$graph->get(AuditRecorder::class)]; }
    public function permissions(): array { return ['audit.read' => 'Read the audit log']; }
}

$polaris = Polaris::create(new Config(..., plugins: [new AuditPlugin()]));
```

What happens at `Polaris::create()`:

| Part | Effect |
| --- | --- |
| `schema()` | The models join `Schema::all()`: `schema:export`, `schema:create`, `schema:diff` and `SchemaInstaller` cover their tables; `UnitOfWork` persists them; a model redefining a core table is rejected. |
| `manifestDirectory()` | The specs join the manifest and the router; a route already declared elsewhere is rejected. Keep the specs under a subdirectory named after the plugin (`api/audit/me.yaml`), because the route names the adapters derive (`polaris.audit.me`) come from the file path. Static, because a host's route table is built before the plugin is configured. |
| `services()` | Factories keyed by class; an endpoint constructor typed with that class gets the service, built once per graph (`Graph::get()` returns the same instance). Core services resolve as before. |
| `listeners()` | Appended to `Polaris::listeners()`, so the host subscribes them with core's three. |
| `permissions()` | Merged into the permission catalog and seeded by `schema:create` and the adapters' install commands. |
| `middleware(Graph)` | PSR-15 middleware run on every Polaris route right after the bearer token was parsed, before step-up, denylist and authorization; where a plugin resolves its own principals (`polaris/admin`) or adds a header. The adapters run the pipeline, so it runs in every host. |

Plugin endpoints extend `Polaris\Http\Endpoint` like core's and read the same `Input`. Their errors are RFC
9457 problem documents through `Endpoint::problem()`: `application/problem+json` with `type`
(`https://polaris.univeros.io/problems/<plugin>/<name>`), `title`, `status`, `detail`, plus `error` and
`message` so a client reading core's envelope reads both. Core's own routes keep their plain envelope.

## The CLI and the adapters

`polaris schema:export|create|drop|diff`, `manifest` and `doctor` take `--bootstrap=<file>` (or
`POLARIS_BOOTSTRAP`), a PHP file returning the application's `Polaris` or `Config`, so they see the
plugins; without it they see core alone. The adapters take the plugins from their configuration:
Laravel `config('polaris.plugins')` (class names, bindings or instances), Symfony `polaris.plugins`
(service ids), Yii `polaris.plugins` params (class names or definitions with `class`); their console
commands and route tables include the plugins' tables and routes.

## The TypeScript client

`@polaris-auth/client` is generated for the application declared in `packages/client-ts/polaris.php`; a
plugin listed there gets a namespace named after its id (`client.admin.listUsers()`), one typed method per
endpoint class, from the `x-polaris-plugin` marker the OpenAPI document puts on its operations. Its errors
type as `ProblemBody`.

## Proving a plugin

A plugin's functional tests extend `Polaris\Tests\Functional\FunctionalTestCase` (shipped in `polaris/core`'s
`tests/`), override `plugins()` with the plugin and `fixtureDirectory()` with their own `tests/Contract/fixtures`.
The first run with `POLARIS_RECORD_FIXTURES=1` records each test's request/response steps from the PSR-15
harness; the recorded files are reviewed and committed; from then on every run replays them, and
`POLARIS_HARNESS=<adapter harness>` replays them through Laravel, Symfony and Yii, as core's 184 fixtures.
