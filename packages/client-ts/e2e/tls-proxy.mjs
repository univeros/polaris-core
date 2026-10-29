// A TLS front for the cookie-mode e2e: https://localhost:<TLS_PORT> forwards to the demo's php -S on
// 127.0.0.1:<TARGET_PORT> with X-Forwarded-Proto: https, the way a TLS-terminating proxy does in production.
// Cookie mode refuses plaintext with no localhost exception (docs/cookie-mode/decisions.md, 2026-10-29),
// so the test runs what production runs. The certificate is self-signed and thrown away; the browser
// context ignores HTTPS errors.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { request } from "node:http";
import { createServer } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";

const listen = Number(process.env.TLS_PORT ?? 8443);
const target = Number(process.env.TARGET_PORT ?? 8091);
const dir = mkdtempSync(join(tmpdir(), "polaris-tls-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "1", "-subj", "/CN=localhost"], { stdio: "ignore" });

createServer({ key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) }, (incoming, outgoing) => {
    const upstream = request(
        { host: "127.0.0.1", port: target, method: incoming.method, path: incoming.url, headers: { ...incoming.headers, "x-forwarded-proto": "https" } },
        (answer) => {
            outgoing.writeHead(answer.statusCode ?? 502, answer.headers);
            answer.pipe(outgoing);
        },
    );
    upstream.on("error", (error) => {
        outgoing.writeHead(502, { "Content-Type": "text/plain" });
        outgoing.end(String(error));
    });
    incoming.pipe(upstream);
}).listen(listen, "localhost", () => console.log(`TLS front on https://localhost:${listen} -> 127.0.0.1:${target}`));
