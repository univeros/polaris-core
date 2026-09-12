import { describe, expect, it } from "vitest";
import { createClient, type ProblemBody } from "../src/index.js";

/**
 * The plugin namespaces against a recording fetch: each method is the route it names, with the
 * client's bearer, and a problem document types as `ProblemBody`.
 */
function recording(status: number, body: unknown) {
    const requests: Request[] = [];
    const fetch = async (input: Request): Promise<Response> => {
        requests.push(input);
        return new Response(JSON.stringify(body), {
            status,
            headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
        });
    };

    return { requests, fetch };
}

describe("client.admin, client.audit, client.sentinel and client.sso", () => {
    it("maps the admin methods onto their routes with the API key as bearer", async () => {
        const { requests, fetch } = recording(200, { data: [], next_cursor: null });
        const client = createClient({ baseUrl: "https://polaris.example/api", token: "pak_secret", fetch });

        const users = await client.admin.listUsers({ params: { query: { status: "active", limit: 10 } } });
        expect(users.data?.next_cursor).toBeNull();
        await client.admin.banUser({ params: { path: { id: "u1" } } });
        await client.admin.updateMemberRoles({ params: { path: { id: "o1", userId: "u2" } }, body: { roles: ["admin"] } });
        await client.admin.revokeAllSessions({ params: { path: { id: "u1" } } });
        await client.admin.stats();

        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}${new URL(request.url).search}`)).toEqual([
            "GET /api/admin/users?status=active&limit=10",
            "POST /api/admin/users/u1/ban",
            "PATCH /api/admin/organizations/o1/members/u2/roles",
            "DELETE /api/admin/users/u1/sessions",
            "GET /api/admin/stats",
        ]);
        expect(requests.every((request) => request.headers.get("Authorization") === "Bearer pak_secret")).toBe(true);
        expect(await requests[2]?.json()).toEqual({ roles: ["admin"] });
    });

    it("maps the audit methods and types a problem document", async () => {
        const problem: ProblemBody = {
            type: "https://polaris.univeros.io/problems/admin/forbidden",
            title: "Forbidden",
            status: 403,
            detail: "The viewer role does not allow this action.",
            error: "admin_forbidden",
            message: "The viewer role does not allow this action.",
        };
        const { requests, fetch } = recording(403, problem);
        const client = createClient({ baseUrl: "https://polaris.example", token: "pak_viewer", fetch });

        const trail = await client.audit.me({ params: { query: { names: "session.signed_in" } } });
        expect(trail.data).toBeUndefined();
        expect(trail.error?.error).toBe("admin_forbidden");
        expect(trail.error?.status).toBe(403);
        const denied = await client.admin.deleteUser({ params: { path: { id: "u1" } } });
        expect(denied.response.status).toBe(403);
        expect(denied.error?.type).toBe(problem.type);

        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}`)).toEqual(["GET /audit/me", "DELETE /admin/users/u1"]);
    });

    it("maps the sentinel methods onto the operator routes", async () => {
        const { requests, fetch } = recording(200, { data: [], next_cursor: null });
        const client = createClient({ baseUrl: "https://polaris.example", token: "pak_owner", fetch });

        await client.sentinel.listDecisions({ params: { query: { action: "block", limit: 5 } } });
        await client.sentinel.createIpRule({ body: { cidr: "198.51.100.0/24", action: "block", note: "scanner" } });
        await client.sentinel.deleteIpRule({ params: { path: { id: "r1" } } });
        await client.sentinel.unblock({ body: { identifier: "ada@example.com" } });
        await client.sentinel.listIpRules();

        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}${new URL(request.url).search}`)).toEqual([
            "GET /admin/sentinel/decisions?action=block&limit=5",
            "POST /admin/sentinel/ip-rules",
            "DELETE /admin/sentinel/ip-rules/r1",
            "POST /admin/sentinel/unblock",
            "GET /admin/sentinel/ip-rules",
        ]);
        expect(await requests[3]?.json()).toEqual({ identifier: "ada@example.com" });
    });

    it("maps the sso methods onto the flow, organization and operator routes", async () => {
        const { requests, fetch } = recording(200, { data: { url: "https://idp.example/authorize", provider_id: "p1", type: "oidc" } });
        const client = createClient({ baseUrl: "https://polaris.example", fetch });

        await client.sso.signIn({ body: { email: "ada@acme.example" } });
        await client.sso.exchange({ body: { code: "c" } });
        await client.withToken("owner").sso.createProvider({ params: { path: { id: "o1" } }, body: { type: "oidc", name: "Okta", issuer: "https://acme.okta.example", config: { client_id: "c" }, redirect_uris: ["https://app.example/done"] } });
        await client.withToken("owner").sso.verifyDomain({ params: { path: { id: "o1", domainId: "d1" } } });
        await client.withToken("pak_owner").sso.adminListProviders({ params: { query: { limit: 5 } } });

        expect(requests.map((request) => `${request.method} ${new URL(request.url).pathname}${new URL(request.url).search}`)).toEqual([
            "POST /sso/sign-in",
            "POST /sso/exchange",
            "POST /orgs/o1/sso/providers",
            "POST /orgs/o1/sso/domains/d1/verify",
            "GET /admin/sso/providers?limit=5",
        ]);
        expect(requests[0]?.headers.get("Authorization")).toBeNull();
        expect(requests[2]?.headers.get("Authorization")).toBe("Bearer owner");
    });

    it("binds the namespaces to the token of each client", async () => {
        const { requests, fetch } = recording(200, { data: [] });
        const anonymous = createClient({ baseUrl: "https://polaris.example", fetch });

        await anonymous.audit.types();
        await anonymous.withToken("access").audit.types();

        expect(requests.map((request) => request.headers.get("Authorization"))).toEqual([null, "Bearer access"]);
    });
});
