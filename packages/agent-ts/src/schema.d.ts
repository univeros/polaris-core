export interface paths {
    "/.well-known/agent-configuration": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Agent protocol discovery */
        get: operations["get_agents_ConfigurationEndpoint"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/register": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Register an agent */
        post: operations["post_agents_RegisterEndpoint"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/enroll": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Enrol an agent through a host */
        post: operations["post_agents_EnrollEndpoint"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/capabilities": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the capabilities */
        get: operations["get_agents_CapabilitiesEndpoint"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/grants/request": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Request capability grants */
        post: operations["post_agents_RequestGrantsEndpoint"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/session": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** The agent's session */
        get: operations["get_agents_SessionEndpoint"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/execute": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Execute a capability */
        post: operations["post_agents_ExecuteEndpoint"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/agents/receipts/{id}/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Verify a receipt */
        get: operations["get_agents_VerifyReceiptEndpoint"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/oauth2/token": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Issue tokens */
        post: operations["post_oauth_TokenEndpoint"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/.well-known/jwks.json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** JWKS document */
        get: operations["get_JwksEndpoint"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        Error: {
            error?: string;
            message?: string;
        };
        ValidationError: {
            errors?: string[];
        };
        /** @description An RFC 9457 problem document, the error shape of the plugins' routes; error and message repeat the core envelope. */
        Problem: {
            /** Format: uri */
            type: string;
            title: string;
            status: number;
            detail: string;
            error: string;
            message: string;
            errors?: string[];
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    get_agents_ConfigurationEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "version": "1.0-draft",
                     *       "provider_name": "Polaris",
                     *       "description": "Polaris for PHP agent provider",
                     *       "issuer": "https://auth.example",
                     *       "default_location": "https://auth.example/agents/execute",
                     *       "algorithms": [
                     *         "ES256",
                     *         "EdDSA"
                     *       ],
                     *       "modes": [
                     *         "delegated",
                     *         "autonomous"
                     *       ],
                     *       "approval_methods": [
                     *         "device_authorization",
                     *         "ciba",
                     *         "in_app"
                     *       ],
                     *       "approval_strengths": {
                     *         "low": "session",
                     *         "medium": "session",
                     *         "high": "step_up"
                     *       },
                     *       "endpoints": {
                     *         "register": "https://auth.example/agents/register",
                     *         "enroll": "https://auth.example/agents/enroll",
                     *         "capabilities": "https://auth.example/agents/capabilities",
                     *         "execute": "https://auth.example/agents/execute",
                     *         "request_capability": "https://auth.example/agents/grants/request",
                     *         "status": "https://auth.example/agents/session",
                     *         "revoke": "https://auth.example/agents",
                     *         "grants": "https://auth.example/agents/grants",
                     *         "approvals": "https://auth.example/agents/approvals",
                     *         "receipts": "https://auth.example/agents/receipts",
                     *         "token": "https://auth.example/oauth2/token"
                     *       },
                     *       "token_endpoint": "https://auth.example/oauth2/token",
                     *       "agent_sdk_versions": {
                     *         "@polaris-auth/agent": "0.10.0",
                     *         "polaris/agent": "0.10.0"
                     *       }
                     *     }
                     */
                    "application/json": {
                        version: string;
                        provider_name: string;
                        description: string;
                        issuer: string;
                        default_location: string;
                        algorithms: string[];
                        modes: string[];
                        approval_methods: string[];
                        approval_strengths: {
                            low: string;
                            medium: string;
                            high: string;
                        };
                        endpoints: {
                            register: string;
                            enroll: string;
                            capabilities: string;
                            execute: string;
                            request_capability: string;
                            status: string;
                            revoke: string;
                            grants: string;
                            approvals: string;
                            receipts: string;
                            token: string;
                        };
                        token_endpoint: string;
                        agent_sdk_versions: {
                            "@polaris-auth/agent": string;
                            "polaris/agent": string;
                        };
                    };
                };
            };
        };
    };
    post_agents_RegisterEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    name: string;
                    /** @enum {string} */
                    mode: "delegated" | "autonomous";
                    /** @enum {string} */
                    auth: "private_key_jwt" | "client_secret" | "delegated_token";
                    jwk?: {
                        [key: string]: unknown;
                    };
                    organization_id?: string;
                    capabilities?: string[];
                };
            };
        };
        responses: {
            /** @description Success */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "id": "018f...",
                     *         "owner_type": "user",
                     *         "owner_id": "018f...",
                     *         "organization_id": "018f...",
                     *         "name": "Deploy bot",
                     *         "mode": "autonomous",
                     *         "host_id": null,
                     *         "auth": "client_secret",
                     *         "public_jwk": null,
                     *         "status": "active",
                     *         "created_by": "018f...",
                     *         "sealed_at": null,
                     *         "created_at": "2026-10-10T10:00:00+00:00",
                     *         "updated_at": "2026-10-10T10:00:00+00:00",
                     *         "client_secret": "pcs_...",
                     *         "grants": [
                     *           {
                     *             "id": "018f...",
                     *             "agent_id": "018f...",
                     *             "capability": "deploy.staging",
                     *             "constraints": [],
                     *             "budget": {
                     *               "kind": "count",
                     *               "total": 100,
                     *               "remaining": 100,
                     *               "field": null
                     *             },
                     *             "status": "active",
                     *             "granted_by": null,
                     *             "approved_via": "auto",
                     *             "approval_id": null,
                     *             "expires_at": null,
                     *             "created_at": "2026-10-10T10:00:00+00:00",
                     *             "updated_at": "2026-10-10T10:00:00+00:00"
                     *           }
                     *         ],
                     *         "approval": null
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            id: string;
                            owner_type: string;
                            owner_id: string;
                            organization_id: string;
                            name: string;
                            mode: string;
                            host_id: string | null;
                            auth: string;
                            public_jwk: string | null;
                            status: string;
                            created_by: string;
                            sealed_at: string | null;
                            created_at: string;
                            updated_at: string;
                            client_secret: string;
                            grants: {
                                id: string;
                                agent_id: string;
                                capability: string;
                                constraints: [
                                ];
                                budget: {
                                    kind: string;
                                    total: number;
                                    remaining: number;
                                    field: string | null;
                                };
                                status: string;
                                granted_by: string | null;
                                approved_via: string;
                                approval_id: string | null;
                                expires_at: string | null;
                                created_at: string;
                                updated_at: string;
                            }[];
                            approval: string | null;
                        };
                    };
                };
            };
            /** @description unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_forbidden */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description capability_not_found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_invalid_input */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    post_agents_EnrollEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    name: string;
                    /** @enum {string} */
                    mode: "delegated" | "autonomous";
                    /** @enum {string} */
                    auth: "private_key_jwt" | "client_secret" | "delegated_token";
                    jwk?: {
                        [key: string]: unknown;
                    };
                };
            };
        };
        responses: {
            /** @description Success */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "id": "018f...",
                     *         "owner_type": "user",
                     *         "owner_id": "018f...",
                     *         "organization_id": "018f...",
                     *         "name": "Claude Code",
                     *         "mode": "delegated",
                     *         "host_id": "018f...",
                     *         "auth": "private_key_jwt",
                     *         "public_jwk": {
                     *           "kty": "EC",
                     *           "crv": "P-256",
                     *           "x": "...",
                     *           "y": "...",
                     *           "alg": "ES256",
                     *           "kid": "...",
                     *           "use": "sig"
                     *         },
                     *         "status": "active",
                     *         "created_by": "018f...",
                     *         "sealed_at": null,
                     *         "created_at": "2026-10-10T10:00:00+00:00",
                     *         "updated_at": "2026-10-10T10:00:00+00:00",
                     *         "grants": [
                     *           {
                     *             "id": "018f...",
                     *             "agent_id": "018f...",
                     *             "capability": "deploy.staging",
                     *             "constraints": [],
                     *             "budget": {
                     *               "kind": "count",
                     *               "total": 100,
                     *               "remaining": 100,
                     *               "field": null
                     *             },
                     *             "status": "active",
                     *             "granted_by": null,
                     *             "approved_via": "auto",
                     *             "approval_id": null,
                     *             "expires_at": null,
                     *             "created_at": "2026-10-10T10:00:00+00:00",
                     *             "updated_at": "2026-10-10T10:00:00+00:00"
                     *           }
                     *         ],
                     *         "approval": {
                     *           "id": "018f...",
                     *           "method": "device_authorization",
                     *           "strength": "step_up",
                     *           "user_code": "BCDF-GHJK",
                     *           "verification_uri": "https://app.example.com/agents/approve",
                     *           "verification_uri_complete": "https://app.example.com/agents/approve?user_code=BCDF-GHJK",
                     *           "expires_in": 600,
                     *           "interval": 5,
                     *           "binding_message": null
                     *         }
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            id: string;
                            owner_type: string;
                            owner_id: string;
                            organization_id: string;
                            name: string;
                            mode: string;
                            host_id: string;
                            auth: string;
                            public_jwk: {
                                kty: string;
                                crv: string;
                                x: string;
                                y: string;
                                alg: string;
                                kid: string;
                                use: string;
                            };
                            status: string;
                            created_by: string;
                            sealed_at: string | null;
                            created_at: string;
                            updated_at: string;
                            grants: {
                                id: string;
                                agent_id: string;
                                capability: string;
                                constraints: [
                                ];
                                budget: {
                                    kind: string;
                                    total: number;
                                    remaining: number;
                                    field: string | null;
                                };
                                status: string;
                                granted_by: string | null;
                                approved_via: string;
                                approval_id: string | null;
                                expires_at: string | null;
                                created_at: string;
                                updated_at: string;
                            }[];
                            approval: {
                                id: string;
                                method: string;
                                strength: string;
                                user_code: string;
                                verification_uri: string;
                                verification_uri_complete: string;
                                expires_in: number;
                                interval: number;
                                binding_message: string | null;
                            };
                        };
                    };
                };
            };
            /** @description agents_unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_invalid_input */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    get_agents_CapabilitiesEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "capabilities": [
                     *           {
                     *             "name": "deploy.staging",
                     *             "description": "Deploy a build to staging",
                     *             "input": {
                     *               "type": "object",
                     *               "properties": {
                     *                 "build": {
                     *                   "type": "string"
                     *                 }
                     *               },
                     *               "required": [
                     *                 "build"
                     *               ]
                     *             },
                     *             "permission": "deploy.staging",
                     *             "risk": "low",
                     *             "grant_status": "active"
                     *           }
                     *         ],
                     *         "next_cursor": null,
                     *         "has_more": false
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            capabilities: {
                                name: string;
                                description: string;
                                input: {
                                    type: string;
                                    properties: {
                                        build: {
                                            type: string;
                                        };
                                    };
                                    required: string[];
                                };
                                permission: string;
                                risk: string;
                                grant_status: string;
                            }[];
                            next_cursor: string | null;
                            has_more: boolean;
                        };
                    };
                };
            };
            /** @description invalid_jwt | agent_inactive */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    post_agents_RequestGrantsEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    capabilities: string[];
                    reason?: string;
                    /** @enum {string} */
                    preferred_method?: "device_authorization" | "ciba" | "in_app";
                    binding_message?: string;
                };
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "agent_id": "018f...",
                     *       "agent_capability_grants": [
                     *         {
                     *           "id": "018f...",
                     *           "agent_id": "018f...",
                     *           "capability": "deploy.staging",
                     *           "constraints": [],
                     *           "budget": {
                     *             "kind": "count",
                     *             "total": 100,
                     *             "remaining": 100,
                     *             "field": null
                     *           },
                     *           "status": "active",
                     *           "granted_by": null,
                     *           "approved_via": "auto",
                     *           "approval_id": null,
                     *           "expires_at": null,
                     *           "created_at": "2026-10-10T10:00:00+00:00",
                     *           "updated_at": "2026-10-10T10:00:00+00:00"
                     *         }
                     *       ],
                     *       "approval": {
                     *         "id": "018f...",
                     *         "method": "device_authorization",
                     *         "strength": "step_up",
                     *         "user_code": "BCDF-GHJK",
                     *         "verification_uri": "https://app.example.com/agents/approve",
                     *         "verification_uri_complete": "https://app.example.com/agents/approve?user_code=BCDF-GHJK",
                     *         "expires_in": 600,
                     *         "interval": 5,
                     *         "binding_message": null
                     *       }
                     *     }
                     */
                    "application/json": {
                        agent_id: string;
                        agent_capability_grants: {
                            id: string;
                            agent_id: string;
                            capability: string;
                            constraints: [
                            ];
                            budget: {
                                kind: string;
                                total: number;
                                remaining: number;
                                field: string | null;
                            };
                            status: string;
                            granted_by: string | null;
                            approved_via: string;
                            approval_id: string | null;
                            expires_at: string | null;
                            created_at: string;
                            updated_at: string;
                        }[];
                        approval: {
                            id: string;
                            method: string;
                            strength: string;
                            user_code: string;
                            verification_uri: string;
                            verification_uri_complete: string;
                            expires_in: number;
                            interval: number;
                            binding_message: string | null;
                        };
                    };
                };
            };
            /** @description unknown_constraint_operator */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_unauthorized | invalid_jwt | aud_mismatch | agent_inactive */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description capability_not_found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_invalid_input */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    get_agents_SessionEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "agent": {
                     *           "id": "018f...",
                     *           "owner_type": "user",
                     *           "owner_id": "018f...",
                     *           "organization_id": "018f...",
                     *           "name": "Deploy bot",
                     *           "mode": "autonomous",
                     *           "host_id": null,
                     *           "auth": "private_key_jwt",
                     *           "public_jwk": {
                     *             "kty": "EC",
                     *             "crv": "P-256",
                     *             "x": "...",
                     *             "y": "...",
                     *             "alg": "ES256",
                     *             "kid": "...",
                     *             "use": "sig"
                     *           },
                     *           "status": "active",
                     *           "created_by": "018f...",
                     *           "sealed_at": null,
                     *           "created_at": "2026-10-10T10:00:00+00:00",
                     *           "updated_at": "2026-10-10T10:00:00+00:00"
                     *         },
                     *         "mode": "autonomous",
                     *         "owner": {
                     *           "type": "user",
                     *           "id": "018f..."
                     *         },
                     *         "organization_id": "018f...",
                     *         "host": null,
                     *         "authenticated_via": "jwt",
                     *         "grants": [
                     *           {
                     *             "id": "018f...",
                     *             "agent_id": "018f...",
                     *             "capability": "deploy.staging",
                     *             "constraints": [],
                     *             "budget": {
                     *               "kind": "count",
                     *               "total": 100,
                     *               "remaining": 100,
                     *               "field": null
                     *             },
                     *             "status": "active",
                     *             "granted_by": null,
                     *             "approved_via": "auto",
                     *             "approval_id": null,
                     *             "expires_at": null,
                     *             "created_at": "2026-10-10T10:00:00+00:00",
                     *             "updated_at": "2026-10-10T10:00:00+00:00"
                     *           }
                     *         ]
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            agent: {
                                id: string;
                                owner_type: string;
                                owner_id: string;
                                organization_id: string;
                                name: string;
                                mode: string;
                                host_id: string | null;
                                auth: string;
                                public_jwk: {
                                    kty: string;
                                    crv: string;
                                    x: string;
                                    y: string;
                                    alg: string;
                                    kid: string;
                                    use: string;
                                };
                                status: string;
                                created_by: string;
                                sealed_at: string | null;
                                created_at: string;
                                updated_at: string;
                            };
                            mode: string;
                            owner: {
                                type: string;
                                id: string;
                            };
                            organization_id: string;
                            host: string | null;
                            authenticated_via: string;
                            grants: {
                                id: string;
                                agent_id: string;
                                capability: string;
                                constraints: [
                                ];
                                budget: {
                                    kind: string;
                                    total: number;
                                    remaining: number;
                                    field: string | null;
                                };
                                status: string;
                                granted_by: string | null;
                                approved_via: string;
                                approval_id: string | null;
                                expires_at: string | null;
                                created_at: string;
                                updated_at: string;
                            }[];
                        };
                    };
                };
            };
            /** @description agents_unauthorized | invalid_jwt | aud_mismatch | agent_inactive */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    post_agents_ExecuteEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    capability: string;
                    arguments?: {
                        [key: string]: unknown;
                    };
                    input?: {
                        [key: string]: unknown;
                    };
                };
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "deployed": true
                     *       },
                     *       "receipt": {
                     *         "id": "018f...",
                     *         "seq": 1,
                     *         "hash": "2c26..."
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            deployed: boolean;
                        };
                        receipt: {
                            id: string;
                            seq: number;
                            hash: string;
                        };
                    };
                };
            };
            /** @description agents_unauthorized | invalid_jwt | aud_mismatch | agent_inactive */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description capability_not_granted | constraint_violated | budget_exhausted */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description capability_not_found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_invalid_arguments */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    get_agents_VerifyReceiptEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "data": {
                     *         "valid": true,
                     *         "checks": {
                     *           "hash": true,
                     *           "signature": true,
                     *           "chain": true
                     *         },
                     *         "receipt": {
                     *           "id": "018f...",
                     *           "agent_id": "018f...",
                     *           "seq": 1,
                     *           "grant_id": "018f...",
                     *           "capability": "deploy.staging",
                     *           "input_hash": "9f86...",
                     *           "outcome": "success",
                     *           "budget_before": 100,
                     *           "budget_after": 99,
                     *           "prev_hash": null,
                     *           "hash": "2c26...",
                     *           "signature": "<jwt>",
                     *           "created_at": "2026-10-10T10:00:00+00:00"
                     *         }
                     *       }
                     *     }
                     */
                    "application/json": {
                        data: {
                            valid: boolean;
                            checks: {
                                hash: boolean;
                                signature: boolean;
                                chain: boolean;
                            };
                            receipt: {
                                id: string;
                                agent_id: string;
                                seq: number;
                                grant_id: string;
                                capability: string;
                                input_hash: string;
                                outcome: string;
                                budget_before: number;
                                budget_after: number;
                                prev_hash: string | null;
                                hash: string;
                                signature: string;
                                created_at: string;
                            };
                        };
                    };
                };
            };
            /** @description unauthorized */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description agents_not_found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    post_oauth_TokenEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": {
                    grant_type: string;
                    client_id?: string;
                    client_secret?: string;
                    client_assertion_type?: string;
                    client_assertion?: string;
                    code?: string;
                    redirect_uri?: string;
                    code_verifier?: string;
                    refresh_token?: string;
                    scope?: string;
                    resource?: string;
                    device_code?: string;
                    auth_req_id?: string;
                    subject_token?: string;
                    subject_token_type?: string;
                    actor_token?: string;
                    actor_token_type?: string;
                    audience?: string;
                };
            };
        };
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "access_token": "<jwt>",
                     *       "token_type": "Bearer",
                     *       "expires_in": 3600,
                     *       "scope": "openid org.read",
                     *       "refresh_token": "prt_...",
                     *       "id_token": "<jwt>"
                     *     }
                     */
                    "application/json": {
                        access_token: string;
                        token_type: string;
                        expires_in: number;
                        scope: string;
                        refresh_token: string;
                        id_token: string;
                    };
                };
            };
            /** @description invalid_request | invalid_grant | unauthorized_client | unsupported_grant_type | invalid_scope | invalid_target | invalid_dpop_proof | authorization_pending | slow_down | access_denied | expired_token */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
            /** @description invalid_client */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["Problem"];
                };
            };
        };
    };
    get_JwksEndpoint: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    /**
                     * @example {
                     *       "keys": [
                     *         {
                     *           "kty": "RSA",
                     *           "use": "sig",
                     *           "alg": "RS256",
                     *           "kid": "2026-06-key",
                     *           "n": "<base64url modulus>",
                     *           "e": "AQAB"
                     *         }
                     *       ]
                     *     }
                     */
                    "application/json": {
                        keys: {
                            kty: string;
                            use: string;
                            alg: string;
                            kid: string;
                            n: string;
                            e: string;
                        }[];
                    };
                };
            };
        };
    };
}
