import { afterEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import { createClient, refreshSession, type paths } from "../src/index.js";

/** A fetch answering 200 with a fresh access token, recording every request it saw. */
function recording() {
    const requests: Request[] = [];
    const fetch = async (input: Request): Promise<Response> => {
        requests.push(input);
        await new Promise((resolve) => setTimeout(resolve, 5));
        return new Response(JSON.stringify({ data: { access_token: `jwt-${requests.length}`, token_type: "Bearer", expires_in: 900 } }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
        });
    };

    return { requests, fetch };
}

afterEach(() => {
    vi.unstubAllGlobals();
});

describe("cookie token delivery", () => {
    it("sends the CSRF header on every request in cookie mode, and nowhere in body mode", async () => {
        const cookie = recording();
        const client = createClient({ baseUrl: "https://polaris.example", fetch: cookie.fetch, tokenDelivery: "cookie" });
        await client.POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });
        await client.withToken("jwt").GET("/auth/me");

        const body = recording();
        await createClient({ baseUrl: "https://polaris.example", fetch: body.fetch }).POST("/auth/login", { body: { email: "ada@example.com", password: "pw" } });

        expect(cookie.requests.map((request) => request.headers.get("X-Polaris-CSRF"))).toEqual(["1", "1"]);
        expect(cookie.requests[1]?.headers.get("Authorization")).toBe("Bearer jwt");
        expect(body.requests[0]?.headers.get("X-Polaris-CSRF")).toBeNull();
    });

    it("refreshes with an empty body under the polaris:refresh lock, one request per call", async () => {
        const names: string[] = [];
        let queue = Promise.resolve();
        vi.stubGlobal("navigator", {
            locks: {
                request: (name: string, callback: () => Promise<unknown>) => {
                    names.push(name);
                    const run = queue.then(callback);
                    queue = run.then(() => undefined, () => undefined);
                    return run;
                },
            },
        });
        const { requests, fetch } = recording();
        const client = createClient({ baseUrl: "https://polaris.example", fetch, tokenDelivery: "cookie" });

        const [first, second] = await Promise.all([refreshSession(client), refreshSession(client)]);

        expect(names).toEqual(["polaris:refresh", "polaris:refresh"]);
        expect(requests).toHaveLength(2);
        expect(requests[0]?.url).toBe("https://polaris.example/auth/token/refresh");
        expect(await requests[0]?.clone().json()).toEqual({});
        expect(requests[0]?.headers.get("X-Polaris-CSRF")).toBe("1");
        expect([first.data?.data.access_token, second.data?.data.access_token]).toEqual(["jwt-1", "jwt-2"]);
    });

    it("shares one in-flight refresh within a tab without Web Locks", async () => {
        vi.stubGlobal("navigator", {});
        const { requests, fetch } = recording();
        const client = createClient({ baseUrl: "https://polaris.example", fetch, tokenDelivery: "cookie" });

        const [first, second] = await Promise.all([refreshSession(client), refreshSession(client)]);
        await refreshSession(client);

        expect(requests).toHaveLength(2);
        expect(first.data?.data.access_token).toBe("jwt-1");
        expect(second).toBe(first);
    });

    it("types the refresh token as optional on the routes that open or rotate a session", () => {
        type Login = paths["/auth/login"]["post"]["responses"][200]["content"]["application/json"];
        type Refreshed = paths["/auth/token/refresh"]["post"]["responses"][200]["content"]["application/json"]["data"];
        type RefreshBody = NonNullable<paths["/auth/token/refresh"]["post"]["requestBody"]>["content"]["application/json"];

        expectTypeOf<Refreshed["refresh_token"]>().toEqualTypeOf<string | undefined>();
        expectTypeOf<{}>().toMatchTypeOf<RefreshBody>();
        expectTypeOf<Extract<Login["data"], { access_token: string }>["refresh_token"]>().toEqualTypeOf<string | undefined>();
    });
});
