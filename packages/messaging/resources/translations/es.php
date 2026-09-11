<?php

declare(strict_types=1);

// The bundled es strings of the messaging templates: `<key>.subject`, `<key>.text`, `<key>.html`.
return [
    'email.verify.subject' => 'Verifica tu dirección de correo',
    'email.verify.text' => 'Bienvenido. Usa este token para verificar tu dirección de correo: {token}',
    'email.reset_password.subject' => 'Restablece tu contraseña',
    'email.reset_password.text' => 'Usa este token para restablecer tu contraseña: {token}
Si no lo has pedido, ignora este mensaje.',
    'email.magic_link.subject' => 'Tu enlace de acceso',
    'email.magic_link.text' => 'Inicia sesión con este enlace: {link}
Solo vale una vez.',
    'email.otp.subject' => 'Tu código de verificación',
    'email.otp.text' => 'Tu código de verificación es {code}. Caduca en {ttl} segundos.',
    'email.invite.subject' => 'Te han invitado a una organización',
    'email.invite.text' => 'Te han invitado a unirte a una organización. Usa este token para aceptar: {token}',
    'email.new_device.subject' => 'Nuevo inicio de sesión en tu cuenta',
    'email.new_device.text' => 'Se ha iniciado sesión en tu cuenta desde un dispositivo nuevo ({ip}, {user_agent}). Si no has sido tú, cambia tu contraseña.',
    'email.password_changed.subject' => 'Tu contraseña ha cambiado',
    'email.password_changed.text' => 'Tu contraseña ha cambiado ({method}). Si no has sido tú, contacta con soporte de inmediato.',
    'email.account_locked.subject' => 'Tu cuenta ha sido bloqueada',
    'email.account_locked.text' => 'Tu cuenta se bloqueó tras varios intentos fallidos de inicio de sesión ({ip}). Se desbloquea pasado un tiempo.',
    'email.mfa_enrolled.subject' => 'Se ha añadido un factor de autenticación',
    'email.mfa_enrolled.text' => 'Se ha añadido un nuevo método de autenticación en dos pasos a tu cuenta.',
    'email.mfa_factor_removed.subject' => 'Se ha eliminado un factor de autenticación',
    'email.mfa_factor_removed.text' => 'Se ha eliminado un método de autenticación en dos pasos de tu cuenta.',
    'email.recovery_codes_regenerated.subject' => 'Tus códigos de recuperación se han regenerado',
    'email.recovery_codes_regenerated.text' => 'Tus códigos de recuperación se han regenerado. Los anteriores ya no sirven.',
    'email.recovery_code_used.subject' => 'Se ha usado un código de recuperación',
    'email.recovery_code_used.text' => 'Se ha usado un código de recuperación para entrar en tu cuenta. Quedan {remaining}.',
    'sms.otp.text' => 'Tu código de verificación es {code}.',
    'sms.new_device.text' => 'Nuevo inicio de sesión en tu cuenta desde {ip}. ¿No has sido tú? Cambia tu contraseña.',
];
