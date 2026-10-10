import { constantTimeEqual, sha256Hex } from "./base64url.js";
import { verify } from "./jws.js";
import type { Jwk } from "./keys.js";
import type { Receipt, ReceiptVerification } from "./types.js";

export const RECEIPT_TYP = "receipt+jwt";

/**
 * Canonical JSON as `Polaris\Agents\Receipts::canonical` makes it: keys sorted at every level, no
 * whitespace, slashes unescaped (PHP's JSON_UNESCAPED_SLASHES) and every non-ASCII character escaped as
 * `\uXXXX` (PHP's default), so the same bytes hash on both sides.
 */
export function canonical(value: unknown): string {
    return JSON.stringify(sorted(value)).replace(/[\u0080-￿]/g, (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function sorted(value: unknown): unknown {
    if (Array.isArray(value)) {
        return value.map(sorted);
    }
    if (value !== null && typeof value === "object") {
        const record = value as Record<string, unknown>;

        return Object.fromEntries(Object.keys(record).sort().map((key) => [key, sorted(record[key])]));
    }

    return value;
}

/** The fields the hash covers, as the server's `Receipt::hashed()` lists them. */
export function hashed(receipt: Receipt): Record<string, unknown> {
    return {
        agent_id: receipt.agent_id,
        budget_after: receipt.budget_after,
        budget_before: receipt.budget_before,
        capability: receipt.capability,
        created_at: receipt.created_at,
        grant_id: receipt.grant_id,
        id: receipt.id,
        input_hash: receipt.input_hash,
        outcome: receipt.outcome,
        prev_hash: receipt.prev_hash,
        seq: receipt.seq,
    };
}

/** SHA-256 (hex) over the canonical JSON of the receipt's fields. */
export function hashOf(receipt: Receipt): Promise<string> {
    return sha256Hex(canonical(hashed(receipt)));
}

/**
 * What `GET /agents/receipts/{id}/verify` does, locally: the hash recomputed from the fields, the
 * `receipt+jwt` signature verified with the server's JWKS and bound to this receipt, and the link to
 * `previous` (its recomputed hash is this receipt's `prev_hash`) when given; the first receipt has none.
 */
export async function verifyReceipt(receipt: Receipt, keys: readonly Jwk[], previous?: Receipt | null): Promise<ReceiptVerification> {
    const recomputed = await hashOf(receipt);
    const hash = constantTimeEqual(recomputed, receipt.hash);
    let signature = false;
    try {
        const { claims } = await verify(receipt.signature, keys, RECEIPT_TYP);
        signature = typeof claims["receipt_hash"] === "string" && constantTimeEqual(claims["receipt_hash"], recomputed)
            && claims["receipt_id"] === receipt.id && claims["agent_id"] === receipt.agent_id && claims["seq"] === receipt.seq;
    } catch {
        signature = false;
    }
    let chain: boolean;
    if (receipt.seq === 1) {
        chain = receipt.prev_hash === null;
    } else if (previous === undefined || previous === null) {
        chain = typeof receipt.prev_hash === "string";
    } else {
        chain = previous.agent_id === receipt.agent_id && previous.seq === receipt.seq - 1 && receipt.prev_hash !== null && constantTimeEqual(await hashOf(previous), receipt.prev_hash);
    }

    return { valid: hash && signature && chain, checks: { hash, signature, chain } };
}
