import type { MaybeOptionalInit } from "openapi-fetch";
import type { paths } from "./schema.js";

type RequiredKeysOf<T> = { [K in keyof T]-?: object extends Pick<T, K> ? never : K }[keyof T];

/**
 * The argument list of a namespaced method: `openapi-fetch`'s init for the route, required when the
 * route has required params or a body, optional otherwise (the same rule as `client.GET(url, init)`).
 */
export type Init<Path extends keyof paths, Method extends keyof paths[Path]> =
    RequiredKeysOf<MaybeOptionalInit<paths[Path], Method>> extends never
        ? [(MaybeOptionalInit<paths[Path], Method> & { [key: string]: unknown })?]
        : [MaybeOptionalInit<paths[Path], Method> & { [key: string]: unknown }];
