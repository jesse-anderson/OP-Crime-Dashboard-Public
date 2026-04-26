// Cloudflare Pages Function: same-origin proxy to a private R2 bucket.
//
// Wired by binding the R2 bucket "opcrime-dashboard" to the variable
// `BUCKET` in the Pages project (Settings -> Functions -> R2 bucket
// bindings). The bucket itself stays private; this function is the only
// reader. Requests come in at /r2/<key> (e.g. /r2/incident_meta.bin) and
// are streamed back from R2.
//
// Security posture (read carefully — none of this is real auth):
//   - Same-origin: the SPA is served from the same hostname, so the
//     browser never sends a cross-origin request and CORS is not needed.
//   - Referer/Origin gate: blocks browser fetches from other websites
//     (a defense against casual hotlinking). Does NOT block scrapers
//     using curl / Python — those headers are trivially forged or
//     omitted. For real abuse protection, add a Cloudflare rate-limit
//     rule on /r2/* in the dashboard.
//   - No CORS headers emitted: cross-origin browser use is intentionally
//     not supported.

const ALLOWED_HOSTS = new Set<string>([
  "opcrimeds.jesse-anderson.net",
  "localhost",
  "127.0.0.1",
]);

interface R2Object {
  body: ReadableStream;
  httpEtag: string;
  size: number;
  writeHttpMetadata(headers: Headers): void;
}

interface R2Bucket {
  get(
    key: string,
    options?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } },
  ): Promise<R2Object | null>;
  head(key: string): Promise<R2Object | null>;
}

interface Env {
  BUCKET: R2Bucket;
}

type PagesFunction<E = unknown> = (context: {
  request: Request;
  env: E;
  params: Record<string, string | string[]>;
}) => Response | Promise<Response>;

function hostnameOf(value: string | null): string | null {
  if (!value) return null;
  try {
    return new URL(value).hostname;
  } catch {
    return null;
  }
}

function originAllowed(request: Request): boolean {
  const refHost = hostnameOf(request.headers.get("Referer"));
  const origHost = hostnameOf(request.headers.get("Origin"));
  // Allow if neither header is present (privacy extensions strip them;
  // do not block legit users). Otherwise at least one must be allowed.
  if (refHost === null && origHost === null) return true;
  if (refHost && ALLOWED_HOSTS.has(refHost)) return true;
  if (origHost && ALLOWED_HOSTS.has(origHost)) return true;
  return false;
}

function contentTypeFor(key: string): string {
  if (key.endsWith(".json")) return "application/json; charset=utf-8";
  return "application/octet-stream";
}

const handler: PagesFunction<Env> = async ({ request, env, params }) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("method not allowed", {
      status: 405,
      headers: { Allow: "GET, HEAD" },
    });
  }
  if (!originAllowed(request)) {
    return new Response("forbidden", { status: 403 });
  }

  const raw = params.path;
  const key = Array.isArray(raw) ? raw.join("/") : raw;
  if (!key || key.includes("..")) {
    return new Response("bad request", { status: 400 });
  }

  // ETag revalidation: if the client supplies If-None-Match, ask R2 to
  // return null (304-shaped) when it still matches.
  const ifNoneMatch = request.headers.get("If-None-Match") ?? undefined;
  const obj = await env.BUCKET.get(
    key,
    ifNoneMatch ? { onlyIf: { etagDoesNotMatch: ifNoneMatch } } : undefined,
  );

  if (obj === null) {
    // Two cases collapse to one. Either the key is missing, or the ETag
    // still matches and R2 returned null. A HEAD probe disambiguates.
    const head = await env.BUCKET.head(key);
    if (head === null) {
      return new Response("not found", { status: 404 });
    }
    return new Response(null, {
      status: 304,
      headers: {
        ETag: head.httpEtag,
        "Cache-Control": "public, max-age=3600, must-revalidate",
      },
    });
  }

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("Content-Type", contentTypeFor(key));
  headers.set("Content-Length", String(obj.size));
  headers.set("ETag", obj.httpEtag);
  headers.set("Cache-Control", "public, max-age=3600, must-revalidate");
  headers.set("X-Content-Type-Options", "nosniff");

  if (request.method === "HEAD") {
    return new Response(null, { status: 200, headers });
  }
  return new Response(obj.body, { status: 200, headers });
};

export const onRequestGet = handler;
export const onRequestHead = handler;
