<?php

declare(strict_types=1);

// The bundled en strings of the messaging templates: `<key>.subject`, `<key>.text`, `<key>.html`.
return [
    'email.verify.subject' => 'Verify your email address',
    'email.verify.text' => 'Welcome. Use this token to verify your email address: {token}',
    'email.verify.html' => '<p>Welcome.</p><p>Use this token to verify your email address: <strong>{token}</strong></p>',
    'email.reset_password.subject' => 'Reset your password',
    'email.reset_password.text' => 'Use this token to reset your password: {token}
If you did not ask for it, ignore this message.',
    'email.reset_password.html' => '<p>Use this token to reset your password: <strong>{token}</strong></p><p>If you did not ask for it, ignore this message.</p>',
    'email.magic_link.subject' => 'Your sign-in link',
    'email.magic_link.text' => 'Sign in with this link: {link}
It is valid once.',
    'email.magic_link.html' => '<p>Sign in with this link: <a href="{link}">{link}</a></p><p>It is valid once.</p>',
    'email.otp.subject' => 'Your verification code',
    'email.otp.text' => 'Your verification code is {code}. It expires in {ttl} seconds.',
    'email.otp.html' => '<p>Your verification code is <strong>{code}</strong>. It expires in {ttl} seconds.</p>',
    'email.invite.subject' => 'You have been invited to an organization',
    'email.invite.text' => 'You have been invited to join an organization. Use this token to accept: {token}',
    'email.invite.html' => '<p>You have been invited to join an organization.</p><p>Use this token to accept: <strong>{token}</strong></p>',
    'email.new_device.subject' => 'A new sign-in to your account',
    'email.new_device.text' => 'Your account was signed in from a new device ({ip}, {user_agent}). If this was not you, change your password.',
    'email.new_device.html' => '<p>Your account was signed in from a new device ({ip}, {user_agent}).</p><p>If this was not you, change your password.</p>',
    'email.password_changed.subject' => 'Your password was changed',
    'email.password_changed.text' => 'Your password was changed ({method}). If this was not you, contact support at once.',
    'email.password_changed.html' => '<p>Your password was changed ({method}).</p><p>If this was not you, contact support at once.</p>',
    'email.account_locked.subject' => 'Your account has been locked',
    'email.account_locked.text' => 'Your account was locked after repeated failed sign-ins ({ip}). It unlocks after a while.',
    'email.account_locked.html' => '<p>Your account was locked after repeated failed sign-ins ({ip}).</p><p>It unlocks after a while.</p>',
    'email.mfa_enrolled.subject' => 'A new authentication factor was added',
    'email.mfa_enrolled.text' => 'A new two-factor authentication method was added to your account.',
    'email.mfa_enrolled.html' => '<p>A new two-factor authentication method was added to your account.</p>',
    'email.mfa_factor_removed.subject' => 'An authentication factor was removed',
    'email.mfa_factor_removed.text' => 'A two-factor authentication method was removed from your account.',
    'email.mfa_factor_removed.html' => '<p>A two-factor authentication method was removed from your account.</p>',
    'email.recovery_codes_regenerated.subject' => 'Your recovery codes were regenerated',
    'email.recovery_codes_regenerated.text' => 'Your recovery codes were regenerated. The previous ones no longer work.',
    'email.recovery_codes_regenerated.html' => '<p>Your recovery codes were regenerated. The previous ones no longer work.</p>',
    'email.recovery_code_used.subject' => 'A recovery code was used',
    'email.recovery_code_used.text' => 'A recovery code was used to sign in to your account. {remaining} remain.',
    'email.recovery_code_used.html' => '<p>A recovery code was used to sign in to your account. {remaining} remain.</p>',
    'sms.otp.text' => 'Your verification code is {code}.',
    'sms.new_device.text' => 'New sign-in to your account from {ip}. Not you? Change your password.',
];
