#!/usr/bin/env bash
# The shared walkthrough (../../walkthrough.sh) on this demo: Laravel serves public/, mail lands in storage/mail.log.
cd "$(dirname "$0")/.." && POLARIS_MAIL_LOG=storage/mail.log POLARIS_SERVER_LOG=storage/logs/server.log exec ../walkthrough.sh
