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

describe("client.admin and client.audit", () => {
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

    it("binds the namespaces to the token of each client", async () => {
        const { requests, fetch } = recording(200, { data: [] });
        const anonymous = createClient({ baseUrl: "https://polaris.example", fetch });

        await anonymous.audit.types();
        await anonymous.withToken("access").audit.types();

        expect(requests.map((request) => request.headers.get("Authorization"))).toEqual([null, "Bearer access"]);
    });
});
