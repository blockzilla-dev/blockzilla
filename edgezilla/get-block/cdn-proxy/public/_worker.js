const INVOCATION_HEADER = "X-Blockzilla-Proxy-Invocation";

function noStore(message, status, invocation) {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8",
    [INVOCATION_HEADER]: invocation,
  });
  if (status === 405) headers.set("Allow", "GET");
  return new Response(`${message}\n`, { status, headers });
}

function publicImmutable(headers) {
  const directives = (headers.get("Cache-Control") ?? "")
    .toLowerCase()
    .split(",")
    .map((value) => value.trim());
  return (
    directives.includes("public") &&
    directives.includes("immutable") &&
    directives.some((value) => /^max-age=[1-9][0-9]*$/.test(value)) &&
    !directives.some((value) => /^(?:private|no-store|no-cache)(?:=|$)/.test(value))
  );
}

export default {
  async fetch(request, env) {
    const invocation = crypto.randomUUID();
    if (request.method !== "GET") {
      return noStore("Use HTTP GET", 405, invocation);
    }
    const url = new URL(request.url);
    if (url.search !== "" || !/^\/block\/[0-9]+\.(?:json|bin)$/.test(url.pathname)) {
      return noStore("Use a block JSON or binary path without a query", 400, invocation);
    }

    try {
      // A new request prevents caller credentials, cookies, conditionals and range
      // headers from changing the block representation or reaching the backend.
      const upstream = await env.GET_BLOCK.fetch(
        new Request(`https://getblock.blockzilla.dev${url.pathname}`, {
          method: "GET",
          redirect: "manual",
        }),
      );
      const headers = new Headers(upstream.headers);
      const hadCookie = headers.has("Set-Cookie");
      headers.delete("Set-Cookie");
      // Only the outer CDN may add these headers to prove an outer cache hit.
      headers.delete("CF-Cache-Status");
      headers.delete("Age");
      headers.set(INVOCATION_HEADER, invocation);
      if (upstream.status !== 200 || hadCookie || !publicImmutable(headers)) {
        headers.set("Cache-Control", "no-store");
        headers.delete("Cloudflare-CDN-Cache-Control");
        headers.delete("CDN-Cache-Control");
      }
      // Transfer ownership of the existing stream. Do not read, clone or tee it.
      return new Response(upstream.body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers,
      });
    } catch {
      return noStore("Block backend is unavailable", 502, invocation);
    }
  },
};
