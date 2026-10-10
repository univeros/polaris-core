/**
 * The shapes the SDK's logic reads. The generated `schema.d.ts` types every route from the manifest's
 * examples (a documented approximation: an example's `null` types as `null`); these are the fields the
 * poller, the executor and the receipt verifier rely on, named as the protocol names them.
 */

export type { paths, operations, components } from "./schema.js";
import type { Jwk } from "./keys.js";

/** The discovery document, `GET <mount>/.well-known/agent-configuration`. */
export interface AgentConfiguration {
    version: string;
    provider_name: string;
    description: string;
    issuer: string;
    default_location: string;
    algorithms: string[];
    modes: string[];
    approval_methods: string[];
    approval_strengths: Record<string, string>;
    endpoints: { register: string; enroll: string; capabilities: string; execute: string; request_capability: string; status: string; revoke: string; grants: string; approvals: string; receipts: string; token: string; mcp?: string };
    token_endpoint: string;
    agent_sdk_versions?: Record<string, string>;
}

export type GrantStatus = "active" | "pending" | "denied" | "revoked" | "exhausted";

export interface Grant {
    id: string;
    agent_id: string;
    capability: string;
    constraints: Record<string, unknown> | unknown[];
    budget: { kind: string; total: number; remaining: number; field: string | null } | null;
    status: GrantStatus;
    granted_by: string | null;
    approved_via: string | null;
    approval_id: string | null;
    expires_at: string | null;
    created_at: string;
    updated_at: string;
}

/** A pending approval, as `POST /agents/grants/request`, `/agents/register` and `/agents/enroll` answer it. */
export interface Approval {
    id: string;
    method: "device_authorization" | "ciba" | "in_app";
    strength: string;
    user_code: string | null;
    verification_uri: string | null;
    verification_uri_complete: string | null;
    expires_in: number;
    interval: number;
    binding_message: string | null;
}

export interface Agent {
    id: string;
    owner_type: string;
    owner_id: string;
    organization_id: string | null;
    name: string;
    mode: "delegated" | "autonomous";
    host_id: string | null;
    auth: "private_key_jwt" | "client_secret" | "delegated_token";
    public_jwk: Jwk | null;
    status: string;
    created_by: string | null;
    sealed_at: string | null;
    created_at: string;
    updated_at: string;
}

/** `POST /agents/register` and `/agents/enroll`: the agent, its grants, the secret once, a pending approval. */
export interface Registered extends Agent {
    client_secret?: string;
    grants: Grant[];
    approval: Approval | null;
}

export interface GrantRequestResult {
    agent_id: string;
    agent_capability_grants: Grant[];
    approval?: Approval | null;
}

export interface Session {
    agent: Agent;
    mode: string;
    owner: { type: string; id: string };
    organization_id: string | null;
    host: { id: string; name: string } | null;
    authenticated_via: "jwt" | "oauth";
    grants: Grant[];
}

export interface Capability {
    name: string;
    description: string;
    input: Record<string, unknown>;
    location?: string;
    permission: string;
    risk: "low" | "medium" | "high";
    grant_status?: "active" | "pending" | "none";
}

export interface ExecuteResult<T = unknown> {
    data: T;
    receipt: { id: string; seq: number; hash: string };
}

/** A receipt as the chain lists it (`GET /agents/{id}/receipts`) or the verify route returns it. */
export interface Receipt {
    id: string;
    agent_id: string;
    seq: number;
    grant_id: string | null;
    capability: string | null;
    input_hash: string;
    outcome: "success" | "failed" | "sealed";
    budget_before: number | null;
    budget_after: number | null;
    prev_hash: string | null;
    hash: string;
    signature: string;
    created_at: string;
}

export interface ReceiptVerification {
    valid: boolean;
    checks: { hash: boolean; signature: boolean; chain: boolean };
}

/** An RFC 6749 token response. */
export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in?: number;
    scope?: string;
    refresh_token?: string;
    issued_token_type?: string;
}

/** The RFC 9457 problem document every refusal of an agents or oauth route carries. */
export interface Problem {
    type: string;
    title: string;
    status: number;
    detail: string;
    error: string;
    message?: string;
    violations?: { field: string; constraint: string; actual: unknown }[];
    [key: string]: unknown;
}
