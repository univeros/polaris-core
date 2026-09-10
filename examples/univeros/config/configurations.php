<?php

declare(strict_types=1);

/*
 * The Configuration chain applied to the container at boot (the Univeros skeleton's default).
 *
 * @return list<Altair\Configuration\Contracts\ConfigurationInterface>
 */
return [
    new Altair\Logging\Configuration\LoggingConfiguration(),
];
