import type { Problem } from "./types.js";

export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

/** A refused call: the HTTP status, the problem document when the server sent one, and its `error` code. */
export class PolarisAgentError extends Error {
    constructor(
        message: string,
        public readonly status: number,
        public readonly problem: Problem | null = null,
        public readonly code: string = problem?.error ?? "request_failed",
    ) {
        super(message);
        this.name = "PolarisAgentError";
    }
}

/** A JSON body sent exactly as `body` says, with the answer parsed; a non-2xx answer is thrown as a `PolarisAgentError`. */
export async function call<T>(fetchImpl: Fetch, url: string, init: { method: string; body?: string; headers?: Record<string, string>; signal?: AbortSignal }): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json", ...init.headers };
    if (init.body !== undefined) {
        headers["Content-Type"] ??= "application/json";
    }
    const request: RequestInit = { method: init.method, headers };
    if (init.body !== undefined) {
        request.body = init.body;
    }
    if (init.signal !== undefined) {
        request.signal = init.signal;
    }
    const response = await fetchImpl(url, request);
    const text = await response.text();
    const parsed = parse(text);
    if (!response.ok) {
        const problem = parsed !== null && typeof parsed["type"] === "string" && typeof parsed["error"] === "string" ? (parsed as unknown as Problem) : null;
        const detail = problem?.detail ?? (typeof parsed?.["message"] === "string" ? String(parsed["message"]) : text.slice(0, 200));
        throw new PolarisAgentError(`${init.method} ${url} answered ${response.status}: ${detail}`, response.status, problem, problem?.error ?? (typeof parsed?.["error"] === "string" ? String(parsed["error"]) : undefined));
    }
    if (parsed === null) {
        throw new PolarisAgentError(`${init.method} ${url} did not answer JSON.`, response.status);
    }

    return parsed as T;
}

function parse(text: string): Record<string, unknown> | null {
    if (text === "") {
        return null;
    }
    try {
        const value: unknown = JSON.parse(text);

        return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
    } catch {
        return null;
    }
}

/** The exact URL a request JWT's `aud` names: scheme, host, port and path, never the query or fragment. */
export function canonicalUrl(url: string): string {
    const index = url.search(/[?#]/);

    return index === -1 ? url : url.slice(0, index);
}

/** A route's path with its `{param}` placeholders filled, under the mount. */
export function routeUrl(baseUrl: string, path: string, params: Record<string, string> = {}): string {
    const filled = path.replace(/\{(\w+)\}/g, (_, name: string) => {
        const value = params[name];
        if (value === undefined) {
            throw new Error(`The route needs ${name}.`);
        }

        return encodeURIComponent(value);
    });

    return `${baseUrl.replace(/\/+$/, "")}${filled}`;
}
