<?php

declare(strict_types=1);

namespace Polaris\Tests\Support\Plugin;

use Override;
use Polaris\Http\Endpoint;
use Polaris\Http\Input;
use Polaris\Http\Result;

/**
 * `GET /sample/notes`: a plugin endpoint whose constructor asks for a plugin service.
 */
final class SampleNotesEndpoint extends Endpoint
{
    public function __construct(private readonly SampleNotes $notes)
    {
    }

    #[Override]
    public function __invoke(Input $input): Result
    {
        if ($input->get('fail') === '1') {
            return $this->problem(403, 'sample/forbidden', 'Forbidden', 'The sample says no.', ['hint' => 'drop ?fail=1']);
        }

        return $this->respond(200, ['data' => $this->notes->all()]);
    }
}
