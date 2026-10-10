import { PolarisAgentError } from "./http.js";
import type { Approval, Grant } from "./types.js";

/** Seconds added to the interval when the server asks to slow down (a 429, or an RFC 8628 `slow_down`). */
export const SLOW_DOWN = 5;

export type ApprovalOutcome = "denied" | "expired" | "aborted";

/** The wait ended without the grants: the approval was denied, expired (or the attempts ran out), or the caller aborted. */
export class ApprovalError extends Error {
    constructor(
        public readonly outcome: ApprovalOutcome,
        public readonly approval: Approval,
        message: string,
    ) {
        super(message);
        this.name = "ApprovalError";
    }
}

export interface WaitOptions {
    signal?: AbortSignal;
    /** A ceiling on the polls, whatever `expires_in` says. */
    maxAttempts?: number;
    /** The pause between polls; the default is a `setTimeout` the signal cancels. */
    sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    now?: () => number;
}

/**
 * Polls `poll()` (the agent's session: its grants with their status) every `approval.interval` seconds
 * until every grant of the approval is `active` (the grants are returned), one is `denied` or `revoked`
 * (`ApprovalError` `denied`), `expires_in` has passed or the attempts are spent (`expired`), or the signal
 * aborts (`aborted`). A 429 or `slow_down` adds five seconds to the interval, as RFC 8628 has it.
 */
export async function waitForApproval(approval: Approval, poll: () => Promise<readonly Grant[]>, options: WaitOptions = {}): Promise<Grant[]> {
    const now = options.now ?? Date.now;
    const sleep = options.sleep ?? pause;
    const deadline = now() + Math.max(1, approval.expires_in) * 1000;
    const maxAttempts = options.maxAttempts ?? Math.ceil(approval.expires_in / Math.max(1, approval.interval)) + 1;
    let interval = Math.max(1, approval.interval);
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        // The next poll would land after the approval expired: nothing left to wait for.
        if (now() + interval * 1000 > deadline) {
            break;
        }
        await sleep(interval * 1000, options.signal);
        if (options.signal?.aborted) {
            throw new ApprovalError("aborted", approval, "The wait for the approval was aborted.");
        }
        let grants: readonly Grant[];
        try {
            grants = await poll();
        } catch (error) {
            if (error instanceof PolarisAgentError && (error.status === 429 || error.code === "slow_down")) {
                interval += SLOW_DOWN;
                continue;
            }
            throw error;
        }
        const mine = grants.filter((grant) => grant.approval_id === approval.id);
        if (mine.some((grant) => grant.status === "denied" || grant.status === "revoked")) {
            throw new ApprovalError("denied", approval, "The approval was denied.");
        }
        if (mine.length > 0 && mine.every((grant) => grant.status === "active")) {
            return [...mine];
        }
    }
    throw new ApprovalError("expired", approval, "The approval expired before it was decided.");
}

function pause(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve) => {
        if (signal?.aborted) {
            resolve();

            return;
        }
        const timer = setTimeout(() => {
            signal?.removeEventListener("abort", onAbort);
            resolve();
        }, ms);
        const onAbort = (): void => {
            clearTimeout(timer);
            resolve();
        };
        signal?.addEventListener("abort", onAbort, { once: true });
    });
}
