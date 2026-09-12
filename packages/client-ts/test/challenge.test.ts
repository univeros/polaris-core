import { describe, expect, it, vi } from "vitest";
import { createClient, type ProblemBody } from "../src/index.js";

const challenge: ProblemBody & { challenge: string } = {
    type: "https://polaris.univeros.io/problems/sentinel/challenge_required",
    title: "Challenge required",
    status: 403,
    detail: "Complete the challenge and try again.",
    error: "sentinel_challenge_required",
    message: "Complete the challenge and try again.",
    challenge: "captcha",
};

/** A fetch answering the given responses in order, recording every request it saw. */
function recording(...answers: Array<{ status: number; body: unknown }>) {
    const requests: Request[] = [];
    const fetch = async (input: Request): Promise<Response> => {
        requests.push(input);
        const answer = answers[Math.min(requests.length, answers.length) - 1] ?? { status: 500, body: {} };
        return new Response(JSON.stringify(answer.body), {
            status: answer.status,
            headers: { "Content-Type": answer.status >= 400 ? "application/problem+json" : "application/json" },
        });
    };

    return { requests, fetch };
}

describe("the sentinel challenge retry", () => {
    it("returns the problem document as any other error without a callback", async () => {
        const { requests, fetch } = recording({ status: 403, body: challenge });
        const client = createClient({ baseUrl: "https://polaris.example", fetch });

        const login = await client.POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });

        expect(login.response.status).toBe(403);
        expect((login.error as { error?: string } | undefined)?.error).toBe("sentinel_challenge_required");
        expect(requests).toHaveLength(1);
    });

    it("asks for a captcha token and retries the same request once with captcha_token in the body", async () => {
        const { requests, fetch } = recording({ status: 403, body: challenge }, { status: 200, body: { data: { access_token: "at", token_type: "Bearer" } } });
        const captcha = vi.fn(async () => "cf-token");
        const client = createClient({ baseUrl: "https://polaris.example/api", token: "mfa", fetch, challenge: { captcha } });

        const login = await client.POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });

        expect(login.response.status).toBe(200);
        expect(login.data).toEqual({ data: { access_token: "at", token_type: "Bearer" } });
        expect(captcha).toHaveBeenCalledTimes(1);
        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual(["POST /api/auth/login", "POST /api/auth/login"]);
        expect(await requests[1]?.json()).toEqual({ email: "ada@example.com", password: "pw", captcha_token: "cf-token" });
        expect(requests[1]?.headers.get("Authorization")).toBe("Bearer mfa");
        expect(requests[1]?.headers.get("Content-Type")).toBe("application/json");
    });

    it("retries once only: a second challenge is returned as is", async () => {
        const { requests, fetch } = recording({ status: 403, body: challenge }, { status: 403, body: challenge });
        const captcha = vi.fn(async () => "wrong");
        const client = createClient({ baseUrl: "https://polaris.example", fetch, challenge: { captcha } });

        const login = await client.POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });

        expect(login.response.status).toBe(403);
        expect(captcha).toHaveBeenCalledTimes(1);
        expect(requests).toHaveLength(2);
    });

    it("leaves every other 403 alone", async () => {
        const forbidden: ProblemBody = { ...challenge, type: "https://polaris.univeros.io/problems/admin/forbidden", error: "admin_forbidden" };
        const { requests, fetch } = recording({ status: 403, body: forbidden });
        const captcha = vi.fn(async () => "cf-token");
        const client = createClient({ baseUrl: "https://polaris.example", token: "pak_viewer", fetch, challenge: { captcha } });

        const denied = await client.admin.stats();

        expect(denied.error?.error).toBe("admin_forbidden");
        expect(captcha).not.toHaveBeenCalled();
        expect(requests).toHaveLength(1);
    });

    it("keeps the challenge callback on the client withToken returns", async () => {
        const { requests, fetch } = recording({ status: 403, body: challenge }, { status: 202, body: { message: "sent" } });
        const captcha = vi.fn(async () => "cf-token");
        const client = createClient({ baseUrl: "https://polaris.example", fetch, challenge: { captcha } });

        const resend = await client.withToken("access").POST("/auth/email/verify/resend", { body: { email: "ada@example.com" } });

        expect(resend.response.status).toBe(202);
        expect(captcha).toHaveBeenCalledTimes(1);
        expect(await requests[1]?.json()).toEqual({ email: "ada@example.com", captcha_token: "cf-token" });
    });
});
