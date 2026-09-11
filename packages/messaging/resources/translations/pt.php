<?php

declare(strict_types=1);

// The bundled pt strings of the messaging templates: `<key>.subject`, `<key>.text`, `<key>.html`.
return [
    'email.verify.subject' => 'Verifique o seu endereço de e-mail',
    'email.verify.text' => 'Bem-vindo. Use este token para verificar o seu endereço de e-mail: {token}',
    'email.reset_password.subject' => 'Redefina a sua senha',
    'email.reset_password.text' => 'Use este token para redefinir a sua senha: {token}
Se não pediu isto, ignore esta mensagem.',
    'email.magic_link.subject' => 'O seu link de acesso',
    'email.magic_link.text' => 'Inicie sessão com este link: {link}
É válido apenas uma vez.',
    'email.otp.subject' => 'O seu código de verificação',
    'email.otp.text' => 'O seu código de verificação é {code}. Expira em {ttl} segundos.',
    'email.invite.subject' => 'Foi convidado para uma organização',
    'email.invite.text' => 'Foi convidado para se juntar a uma organização. Use este token para aceitar: {token}',
    'email.new_device.subject' => 'Novo início de sessão na sua conta',
    'email.new_device.text' => 'A sua conta foi acedida a partir de um novo dispositivo ({ip}, {user_agent}). Se não foi você, altere a sua senha.',
    'email.password_changed.subject' => 'A sua senha foi alterada',
    'email.password_changed.text' => 'A sua senha foi alterada ({method}). Se não foi você, contacte o suporte de imediato.',
    'email.account_locked.subject' => 'A sua conta foi bloqueada',
    'email.account_locked.text' => 'A sua conta foi bloqueada após várias tentativas falhadas de início de sessão ({ip}). Será desbloqueada após algum tempo.',
    'email.mfa_enrolled.subject' => 'Foi adicionado um fator de autenticação',
    'email.mfa_enrolled.text' => 'Foi adicionado um novo método de autenticação em dois passos à sua conta.',
    'email.mfa_factor_removed.subject' => 'Foi removido um fator de autenticação',
    'email.mfa_factor_removed.text' => 'Foi removido um método de autenticação em dois passos da sua conta.',
    'email.recovery_codes_regenerated.subject' => 'Os seus códigos de recuperação foram regenerados',
    'email.recovery_codes_regenerated.text' => 'Os seus códigos de recuperação foram regenerados. Os anteriores já não funcionam.',
    'email.recovery_code_used.subject' => 'Foi usado um código de recuperação',
    'email.recovery_code_used.text' => 'Foi usado um código de recuperação para entrar na sua conta. Restam {remaining}.',
    'sms.otp.text' => 'O seu código de verificação é {code}.',
    'sms.new_device.text' => 'Novo início de sessão na sua conta a partir de {ip}. Não foi você? Altere a sua senha.',
];
