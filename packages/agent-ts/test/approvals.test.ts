import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApprovalError, waitForApproval } from "../src/approvals.js";
import { PolarisAgentError } from "../src/http.js";
import { approval, grant } from "./support.js";

const pending = () => [grant({ id: "g2", capability: "org.rename", status: "pending", approval_id: "ap1" }), grant({ id: "g1", status: "active" })];
const active = () => [grant({ id: "g2", capability: "org.rename", status: "active", approval_id: "ap1" }), grant({ id: "g1", status: "active" })];

describe("waitForApproval", () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    it("polls at the interval, slows down by five seconds on a 429, and returns the approval's grants once active", async () => {
        const polls: number[] = [];
        const answers = [() => pending(), () => { throw new PolarisAgentError("429", 429); }, () => pending(), () => active()];
        const poll = async () => { polls.push(Date.now()); return answers[polls.length - 1]!(); };
        const start = Date.now();
        const waiting = waitForApproval(approval({ interval: 5, expires_in: 600 }), poll);
        await vi.advanceTimersByTimeAsync(5_000 + 5_000 + 10_000 + 10_000);
        const grants = await waiting;
        expect(grants.map((item) => item.id)).toEqual(["g2"]);
        expect(polls.map((at) => (at - start) / 1000)).toEqual([5, 10, 20, 30]);
    });

    it("ends as denied when a grant of the approval is denied", async () => {
        const waiting = waitForApproval(approval(), async () => [grant({ id: "g2", status: "denied", approval_id: "ap1" })]);
        const caught = waiting.catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(5_000);
        expect(await caught).toBeInstanceOf(ApprovalError);
        expect(await caught).toMatchObject({ outcome: "denied" });
    });

    it("ends as expired after expires_in, and never polls more than maxAttempts times", async () => {
        let polls = 0;
        const waiting = waitForApproval(approval({ interval: 5, expires_in: 12 }), async () => { polls += 1; return pending(); });
        const caught = waiting.catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(60_000);
        expect(await caught).toMatchObject({ outcome: "expired" });
        expect(polls).toBe(2);

        polls = 0;
        const bounded = waitForApproval(approval({ interval: 1, expires_in: 600 }), async () => { polls += 1; return pending(); }, { maxAttempts: 3 }).catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(10_000);
        expect(await bounded).toMatchObject({ outcome: "expired" });
        expect(polls).toBe(3);
    });

    it("stops at once when the signal aborts", async () => {
        const controller = new AbortController();
        let polls = 0;
        const waiting = waitForApproval(approval({ interval: 30 }), async () => { polls += 1; return pending(); }, { signal: controller.signal }).catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(1_000);
        controller.abort();
        await vi.advanceTimersByTimeAsync(0);
        expect(await waiting).toMatchObject({ outcome: "aborted" });
        expect(polls).toBe(0);
    });

    it("rethrows any other error of the poll", async () => {
        const waiting = waitForApproval(approval(), async () => { throw new PolarisAgentError("gone", 401); }).catch((error: unknown) => error);
        await vi.advanceTimersByTimeAsync(5_000);
        expect(await waiting).toMatchObject({ status: 401 });
    });
});
