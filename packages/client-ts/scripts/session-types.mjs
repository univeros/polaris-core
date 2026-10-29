// Cookie token delivery (docs/cookie-mode/spec.md §2.9): the client's types mark `data.refresh_token`
// optional on the operations whose spec says `x-polaris-session: issue | refresh`, and `refresh_token`
// optional in the refresh request body, since a cookie-mode server omits the first and fills the second
// from the cookie. openapi.json stays the manifest's own output (the MCP tools and the drift check read
// it as is); this writes the adjusted copy openapi-typescript reads.
// Usage: node scripts/session-types.mjs <openapi.json> <out.json>
import { readFileSync, writeFileSync } from "node:fs";

const [input, output] = process.argv.slice(2);
if (input === undefined || output === undefined) {
    throw new Error("usage: session-types.mjs <openapi.json> <out.json>");
}
const document = JSON.parse(readFileSync(input, "utf8"));

const withoutRefreshToken = (required) => (Array.isArray(required) ? required.filter((key) => key !== "refresh_token") : required);

function optionalInData(schema) {
    if (schema === undefined || schema === null) {
        return;
    }
    for (const variant of schema.oneOf ?? []) {
        optionalInData(variant);
    }
    const data = schema.properties?.data;
    if (data?.required !== undefined) {
        data.required = withoutRefreshToken(data.required);
    }
}

let marked = 0;
for (const operations of Object.values(document.paths ?? {})) {
    for (const operation of Object.values(operations)) {
        const session = operation?.["x-polaris-session"];
        if (session !== "issue" && session !== "refresh") {
            continue;
        }
        marked += 1;
        for (const response of Object.values(operation.responses ?? {})) {
            optionalInData(response.content?.["application/json"]?.schema);
        }
        if (session === "refresh") {
            const body = operation.requestBody?.content?.["application/json"]?.schema;
            if (body !== undefined) {
                body.required = withoutRefreshToken(body.required);
                if (body.required?.length === 0) {
                    delete body.required;
                }
            }
        }
    }
}

writeFileSync(output, JSON.stringify(document));
console.log(`${output}: refresh_token optional on ${marked} operations`);
