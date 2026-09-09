# Effect classification of the 52 endpoints

Generated from `api/**/*.yaml` at v1.0.0. This is the table WP5 writes into each spec as `endpoint.effect` and `endpoint.receipt`.
Rule: `GET` → `read`; `DELETE`, `logout-all`, `recovery-codes/regenerate`, and `users/disable` → `destructive`; everything else → `write`. `receipt` defaults to `true` for write/destructive and `false` for read.

Review before applying: `users/disable` is classified destructive deliberately (it locks a person out); `logout` is `write` because it only affects the caller's own session. Change the table, not the code, if you disagree, and record the reason in `decisions.md`.

| Spec file | Method | Path | Auth | effect | receipt | Endpoint class (after WP5) |
|---|---|---|---|---|---|---|
| `auth/email-verify-resend.yaml` | POST | `/auth/email/verify/resend` | public | **write** | true | `ResendVerificationEndpoint` |
| `auth/email-verify.yaml` | POST | `/auth/email/verify` | public | **write** | true | `VerifyEmailEndpoint` |
| `auth/invites-accept.yaml` | POST | `/auth/invites/accept` | bearer | **write** | true | `AcceptInviteEndpoint` |
| `auth/jwks.yaml` | GET | `/auth/.well-known/jwks.json` | public | **read** | false | `JwksEndpoint` |
| `auth/login.yaml` | POST | `/auth/login` | public | **write** | true | `LoginEndpoint` |
| `auth/logout-all.yaml` | POST | `/auth/logout-all` | bearer | **destructive** | true | `LogoutAllEndpoint` |
| `auth/logout.yaml` | POST | `/auth/logout` | bearer | **write** | true | `LogoutEndpoint` |
| `auth/me.yaml` | GET | `/auth/me` | bearer | **read** | false | `MeEndpoint` |
| `auth/mfa/challenge.yaml` | POST | `/auth/mfa/challenge` | mfa_token | **write** | true | `MfaChallengeEndpoint` |
| `auth/mfa/email-confirm.yaml` | POST | `/auth/mfa/email/confirm` | bearer | **write** | true | `OtpFactorConfirmEndpoint` |
| `auth/mfa/email-enroll.yaml` | POST | `/auth/mfa/email/enroll` | bearer | **write** | true | `EmailEnrollEndpoint` |
| `auth/mfa/factor-delete.yaml` | DELETE | `/auth/mfa/factors/{id}` | bearer | **destructive** | true | `DeleteFactorEndpoint` |
| `auth/mfa/factor-update.yaml` | PATCH | `/auth/mfa/factors/{id}` | bearer | **write** | true | `UpdateFactorEndpoint` |
| `auth/mfa/factors-list.yaml` | GET | `/auth/mfa/factors` | bearer | **read** | false | `MfaFactorsEndpoint` |
| `auth/mfa/recovery-codes-regenerate.yaml` | POST | `/auth/mfa/recovery-codes/regenerate` | bearer | **destructive** | true | `RegenerateRecoveryCodesEndpoint` |
| `auth/mfa/sms-confirm.yaml` | POST | `/auth/mfa/sms/confirm` | bearer | **write** | true | `OtpFactorConfirmEndpoint` |
| `auth/mfa/sms-enroll.yaml` | POST | `/auth/mfa/sms/enroll` | bearer | **write** | true | `SmsEnrollEndpoint` |
| `auth/mfa/step-up-challenge.yaml` | POST | `/auth/mfa/step-up/challenge` | bearer | **write** | true | `StepUpChallengeEndpoint` |
| `auth/mfa/step-up.yaml` | POST | `/auth/mfa/step-up` | bearer | **write** | true | `StepUpVerifyEndpoint` |
| `auth/mfa/totp-confirm.yaml` | POST | `/auth/mfa/totp/confirm` | bearer | **write** | true | `TotpConfirmEndpoint` |
| `auth/mfa/totp-enroll.yaml` | POST | `/auth/mfa/totp/enroll` | bearer | **write** | true | `TotpEnrollEndpoint` |
| `auth/mfa/verify.yaml` | POST | `/auth/mfa/verify` | mfa_token | **write** | true | `MfaVerifyEndpoint` |
| `auth/password/change.yaml` | POST | `/auth/password/change` | bearer | **write** | true | `ChangePasswordEndpoint` |
| `auth/password/forgot.yaml` | POST | `/auth/password/forgot` | public | **write** | true | `ForgotPasswordEndpoint` |
| `auth/password/reset.yaml` | POST | `/auth/password/reset` | public | **write** | true | `ResetPasswordEndpoint` |
| `auth/register.yaml` | POST | `/auth/register` | public | **write** | true | `RegisterEndpoint` |
| `auth/session-revoke.yaml` | DELETE | `/auth/sessions/{id}` | bearer | **destructive** | true | `RevokeSessionEndpoint` |
| `auth/sessions-list.yaml` | GET | `/auth/sessions` | bearer | **read** | false | `SessionsEndpoint` |
| `auth/switch-org.yaml` | POST | `/auth/switch-org` | bearer | **write** | true | `SwitchOrgEndpoint` |
| `auth/token-refresh.yaml` | POST | `/auth/token/refresh` | public | **write** | true | `RefreshTokenEndpoint` |
| `orgs/create.yaml` | POST | `/orgs` | bearer | **write** | true | `CreateOrganizationEndpoint` |
| `orgs/delete.yaml` | DELETE | `/orgs/{id}` | bearer | **destructive** | true | `DeleteOrganizationEndpoint` |
| `orgs/invite-revoke.yaml` | DELETE | `/orgs/{id}/invites/{inviteId}` | bearer | **destructive** | true | `RevokeInviteEndpoint` |
| `orgs/invites-create.yaml` | POST | `/orgs/{id}/invites` | bearer | **write** | true | `CreateInviteEndpoint` |
| `orgs/invites-list.yaml` | GET | `/orgs/{id}/invites` | bearer | **read** | false | `ListInvitesEndpoint` |
| `orgs/list.yaml` | GET | `/orgs` | bearer | **read** | false | `ListOrganizationsEndpoint` |
| `orgs/member-remove.yaml` | DELETE | `/orgs/{id}/members/{userId}` | bearer | **destructive** | true | `RemoveMemberEndpoint` |
| `orgs/member-roles-update.yaml` | PATCH | `/orgs/{id}/members/{userId}/roles` | bearer | **write** | true | `ChangeMemberRolesEndpoint` |
| `orgs/member-status-update.yaml` | PATCH | `/orgs/{id}/members/{userId}` | bearer | **write** | true | `ChangeMemberStatusEndpoint` |
| `orgs/members-list.yaml` | GET | `/orgs/{id}/members` | bearer | **read** | false | `ListMembersEndpoint` |
| `orgs/read.yaml` | GET | `/orgs/{id}` | bearer | **read** | false | `ReadOrganizationEndpoint` |
| `orgs/role-delete.yaml` | DELETE | `/orgs/{id}/roles/{roleId}` | bearer | **destructive** | true | `DeleteRoleEndpoint` |
| `orgs/role-update.yaml` | PATCH | `/orgs/{id}/roles/{roleId}` | bearer | **write** | true | `UpdateRoleEndpoint` |
| `orgs/roles-create.yaml` | POST | `/orgs/{id}/roles` | bearer | **write** | true | `CreateRoleEndpoint` |
| `orgs/roles-list.yaml` | GET | `/orgs/{id}/roles` | bearer | **read** | false | `ListRolesEndpoint` |
| `orgs/update.yaml` | PATCH | `/orgs/{id}` | bearer | **write** | true | `UpdateOrganizationEndpoint` |
| `permissions/list.yaml` | GET | `/permissions` | bearer | **read** | false | `ListPermissionsEndpoint` |
| `users/delete.yaml` | DELETE | `/users/{id}` | bearer | **destructive** | true | `DeleteUserEndpoint` |
| `users/disable.yaml` | POST | `/users/{id}/disable` | bearer | **destructive** | true | `DisableUserEndpoint` |
| `users/enable.yaml` | POST | `/users/{id}/enable` | bearer | **write** | true | `EnableUserEndpoint` |
| `users/read.yaml` | GET | `/users/{id}` | bearer | **read** | false | `ReadUserEndpoint` |
| `users/update.yaml` | PATCH | `/users/{id}` | bearer | **write** | true | `UpdateUserEndpoint` |

Totals: 11 read · 31 write · 10 destructive.
