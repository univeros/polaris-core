/** base64url (RFC 4648 §5, no padding) over bytes and UTF-8 strings, as JOSE uses it; no Node built-ins. */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function encodeBytes(bytes: Uint8Array | ArrayBuffer): string {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let binary = "";
    for (const byte of view) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function encodeText(text: string): string {
    return encodeBytes(encoder.encode(text));
}

export function decodeBytes(encoded: string): Uint8Array {
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(encoded.length / 4) * 4, "=");
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
}

export function decodeText(encoded: string): string {
    return decoder.decode(decodeBytes(encoded));
}

/** The decoded JSON of one base64url segment (a JWS header or payload); throws on anything else. */
export function decodeJson(encoded: string): Record<string, unknown> {
    const parsed: unknown = JSON.parse(decodeText(encoded));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("The segment is not a JSON object.");
    }

    return parsed as Record<string, unknown>;
}

/** base64url of the SHA-256 of the exact bytes (a request body, a canonical JWK). */
export async function sha256(bytes: Uint8Array | string): Promise<string> {
    const input = typeof bytes === "string" ? encoder.encode(bytes) : bytes;

    return encodeBytes(await crypto.subtle.digest("SHA-256", input as BufferSource));
}

/** The SHA-256 of a string as lowercase hex, as PHP's `hash('sha256', ...)` prints it. */
export async function sha256Hex(text: string): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));

    return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** Equal without an early exit on the first differing character, for comparing hashes. */
export function constantTimeEqual(left: string, right: string): boolean {
    const a = encoder.encode(left);
    const b = encoder.encode(right);
    let difference = a.length ^ b.length;
    for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
        difference |= (a[index % a.length] ?? 0) ^ (b[index % b.length] ?? 0);
    }

    return difference === 0;
}
