<?php

declare(strict_types=1);

// The bundled fr strings of the messaging templates: `<key>.subject`, `<key>.text`, `<key>.html`.
return [
    'email.verify.subject' => 'Vérifiez votre adresse e-mail',
    'email.verify.text' => 'Bienvenue. Utilisez ce jeton pour vérifier votre adresse e-mail : {token}',
    'email.reset_password.subject' => 'Réinitialisez votre mot de passe',
    'email.reset_password.text' => 'Utilisez ce jeton pour réinitialiser votre mot de passe : {token}
Si vous ne l’avez pas demandé, ignorez ce message.',
    'email.magic_link.subject' => 'Votre lien de connexion',
    'email.magic_link.text' => 'Connectez-vous avec ce lien : {link}
Il n’est valable qu’une fois.',
    'email.otp.subject' => 'Votre code de vérification',
    'email.otp.text' => 'Votre code de vérification est {code}. Il expire dans {ttl} secondes.',
    'email.invite.subject' => 'Vous êtes invité à rejoindre une organisation',
    'email.invite.text' => 'Vous êtes invité à rejoindre une organisation. Utilisez ce jeton pour accepter : {token}',
    'email.new_device.subject' => 'Nouvelle connexion à votre compte',
    'email.new_device.text' => 'Votre compte a été utilisé depuis un nouvel appareil ({ip}, {user_agent}). Si ce n’était pas vous, changez votre mot de passe.',
    'email.password_changed.subject' => 'Votre mot de passe a été modifié',
    'email.password_changed.text' => 'Votre mot de passe a été modifié ({method}). Si ce n’était pas vous, contactez le support immédiatement.',
    'email.account_locked.subject' => 'Votre compte a été verrouillé',
    'email.account_locked.text' => 'Votre compte a été verrouillé après plusieurs échecs de connexion ({ip}). Il sera déverrouillé après un délai.',
    'email.mfa_enrolled.subject' => 'Un facteur d’authentification a été ajouté',
    'email.mfa_enrolled.text' => 'Une nouvelle méthode d’authentification à deux facteurs a été ajoutée à votre compte.',
    'email.mfa_factor_removed.subject' => 'Un facteur d’authentification a été retiré',
    'email.mfa_factor_removed.text' => 'Une méthode d’authentification à deux facteurs a été retirée de votre compte.',
    'email.recovery_codes_regenerated.subject' => 'Vos codes de récupération ont été régénérés',
    'email.recovery_codes_regenerated.text' => 'Vos codes de récupération ont été régénérés. Les anciens ne fonctionnent plus.',
    'email.recovery_code_used.subject' => 'Un code de récupération a été utilisé',
    'email.recovery_code_used.text' => 'Un code de récupération a servi à se connecter à votre compte. Il en reste {remaining}.',
    'sms.otp.text' => 'Votre code de vérification est {code}.',
    'sms.new_device.text' => 'Nouvelle connexion à votre compte depuis {ip}. Ce n’est pas vous ? Changez votre mot de passe.',
];
