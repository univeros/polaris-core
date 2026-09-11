<?php

declare(strict_types=1);

// The bundled de strings of the messaging templates: `<key>.subject`, `<key>.text`, `<key>.html`.
return [
    'email.verify.subject' => 'Bestätige deine E-Mail-Adresse',
    'email.verify.text' => 'Willkommen. Bestätige deine E-Mail-Adresse mit diesem Token: {token}',
    'email.reset_password.subject' => 'Passwort zurücksetzen',
    'email.reset_password.text' => 'Setze dein Passwort mit diesem Token zurück: {token}
Falls du das nicht angefordert hast, ignoriere diese Nachricht.',
    'email.magic_link.subject' => 'Dein Anmeldelink',
    'email.magic_link.text' => 'Melde dich mit diesem Link an: {link}
Er gilt nur einmal.',
    'email.otp.subject' => 'Dein Bestätigungscode',
    'email.otp.text' => 'Dein Bestätigungscode lautet {code}. Er läuft in {ttl} Sekunden ab.',
    'email.invite.subject' => 'Du wurdest in eine Organisation eingeladen',
    'email.invite.text' => 'Du wurdest eingeladen, einer Organisation beizutreten. Nimm mit diesem Token an: {token}',
    'email.new_device.subject' => 'Neue Anmeldung bei deinem Konto',
    'email.new_device.text' => 'Dein Konto wurde von einem neuen Gerät aus angemeldet ({ip}, {user_agent}). Warst du das nicht, ändere dein Passwort.',
    'email.password_changed.subject' => 'Dein Passwort wurde geändert',
    'email.password_changed.text' => 'Dein Passwort wurde geändert ({method}). Warst du das nicht, wende dich sofort an den Support.',
    'email.account_locked.subject' => 'Dein Konto wurde gesperrt',
    'email.account_locked.text' => 'Dein Konto wurde nach mehreren fehlgeschlagenen Anmeldungen gesperrt ({ip}). Es wird nach einer Weile entsperrt.',
    'email.mfa_enrolled.subject' => 'Ein Authentifizierungsfaktor wurde hinzugefügt',
    'email.mfa_enrolled.text' => 'Deinem Konto wurde eine neue Zwei-Faktor-Methode hinzugefügt.',
    'email.mfa_factor_removed.subject' => 'Ein Authentifizierungsfaktor wurde entfernt',
    'email.mfa_factor_removed.text' => 'Eine Zwei-Faktor-Methode wurde aus deinem Konto entfernt.',
    'email.recovery_codes_regenerated.subject' => 'Deine Wiederherstellungscodes wurden erneuert',
    'email.recovery_codes_regenerated.text' => 'Deine Wiederherstellungscodes wurden erneuert. Die alten gelten nicht mehr.',
    'email.recovery_code_used.subject' => 'Ein Wiederherstellungscode wurde verwendet',
    'email.recovery_code_used.text' => 'Ein Wiederherstellungscode wurde für die Anmeldung bei deinem Konto verwendet. {remaining} verbleiben.',
    'sms.otp.text' => 'Dein Bestätigungscode lautet {code}.',
    'sms.new_device.text' => 'Neue Anmeldung bei deinem Konto von {ip}. Nicht du? Ändere dein Passwort.',
];
