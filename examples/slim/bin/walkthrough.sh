#!/usr/bin/env bash
# The shared walkthrough (../../walkthrough.sh) on this demo: Slim serves public/ with public/index.php as the
# built-in server's router (the /.well-known routes), mail lands in var/mail.log.
cd "$(dirname "$0")/.." && POLARIS_ROUTER=public/index.php POLARIS_AGENTS=required exec ../walkthrough.sh
