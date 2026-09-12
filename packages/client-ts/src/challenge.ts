import type { Middleware } from "openapi-fetch";

/** How the client answers a challenge of `polaris/sentinel`. */
export interface ChallengeOptions {
    /**
     * Asked for a captcha token when a request answers `403` with the `sentinel/challenge_required` problem
     * and `challenge: captcha`; the same request is then sent once more with `captcha_token` added to its
     * JSON body. The token comes from the captcha widget the host renders (Turnstile, hCaptcha).
     */
    captcha: () => Promise<string>;
}

const CHALLENGE_ERROR = "sentinel_challenge_required";
const CAPTCHA = "captcha";

/**
 * The transparent challenge retry: the body of every request is kept by its id until the response is
 * in; a captcha challenge asks the host for a token and replays the request once with it. Any other
 * response, and the retried response itself, come back as they are, so a wrong token is one problem
 * document and never a loop.
 */
export function challengeRetry(challenge: ChallengeOptions): Middleware {
    const bodies = new Map<string, string>();

    return {
        async onRequest({ id, request }) {
            bodies.set(id, await request.clone().text());
        },
        async onResponse({ id, request, response, options }) {
            const body = bodies.get(id) ?? "";
            bodies.delete(id);
            if (response.status !== 403 || !(await isCaptchaChallenge(response))) {
                return undefined;
            }
            const token = await challenge.captcha();

            return options.fetch(
                new Request(request.url, {
                    method: request.method,
                    headers: request.headers,
                    body: withCaptchaToken(body, token),
                    credentials: request.credentials,
                    signal: request.signal,
                }),
            );
        },
    };
}

async function isCaptchaChallenge(response: Response): Promise<boolean> {
    try {
        const problem: unknown = await response.clone().json();

        return (
            typeof problem === "object" &&
            problem !== null &&
            (problem as { error?: unknown }).error === CHALLENGE_ERROR &&
            (problem as { challenge?: unknown }).challenge === CAPTCHA
        );
    } catch {
        return false;
    }
}

function withCaptchaToken(body: string, token: string): string {
    let parsed: unknown = {};
    if (body !== "") {
        try {
            parsed = JSON.parse(body);
        } catch {
            parsed = {};
        }
    }
    const fields = typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed : {};

    return JSON.stringify({ ...fields, captcha_token: token });
}
