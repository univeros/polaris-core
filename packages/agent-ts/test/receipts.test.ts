import { describe, expect, it } from "vitest";
import { canonical, hashOf, verifyReceipt } from "../src/receipts.js";
import { receipt, serverKey, signReceipt } from "./support.js";

describe("receipts", () => {
    it("canonicalises and hashes exactly as Polaris\\Agents\\Receipts does (a PHP-computed vector)", async () => {
        const fields = receipt({ capability: "café/échec" });
        expect(canonical({ seq: 1, b: [{ z: 1, a: "/" }], a: null })).toBe('{"a":null,"b":[{"a":"/","z":1}],"seq":1}');
        expect(await hashOf(fields)).toBe("9b5f1f690cca6b3b9dd055a71d13ebd6f8a0a7efcd529befc560383e477f836d");
    });

    it.each(["RS256", "EdDSA"] as const)("verifies a receipt signed with the server's %s key, its chain, and detects a tampered one", async (alg) => {
        const server = await serverKey(alg);
        const keys = [{ kty: "RSA", kid: "other", n: "x", e: "AQAB" }, server.jwk];
        const first = receipt();
        const firstHash = await hashOf(first);
        const signedFirst = { ...first, hash: firstHash, signature: await signReceipt(server, first, firstHash) };
        expect(await verifyReceipt(signedFirst, keys)).toEqual({ valid: true, checks: { hash: true, signature: true, chain: true } });

        const second = receipt({ id: "r2", seq: 2, prev_hash: firstHash, budget_before: 99, budget_after: 98 });
        const secondHash = await hashOf(second);
        const signedSecond = { ...second, hash: secondHash, signature: await signReceipt(server, second, secondHash) };
        expect(await verifyReceipt(signedSecond, keys, signedFirst)).toEqual({ valid: true, checks: { hash: true, signature: true, chain: true } });
        expect((await verifyReceipt(signedSecond, keys)).checks.chain).toBe(true);

        // A field changed after signing: the hash and the signature no longer match; the successor's link breaks too.
        const tampered = { ...signedFirst, budget_after: 1 };
        expect(await verifyReceipt(tampered, keys)).toEqual({ valid: false, checks: { hash: false, signature: false, chain: true } });
        expect((await verifyReceipt(signedSecond, keys, tampered)).checks).toEqual({ hash: true, signature: true, chain: false });

        // A receipt re-signed by someone else, a wrong typ, or a first receipt claiming a predecessor.
        const forger = await serverKey(alg);
        expect((await verifyReceipt({ ...signedFirst, signature: await signReceipt(forger, first, firstHash) }, keys)).checks.signature).toBe(false);
        expect((await verifyReceipt({ ...signedFirst, prev_hash: "x" }, keys)).checks).toMatchObject({ hash: false, chain: false });
        expect((await verifyReceipt({ ...signedSecond, signature: signedFirst.signature }, keys, signedFirst)).checks.signature).toBe(false);
    });
});
