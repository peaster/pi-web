import { timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";

/**
 * Network-facing request guard for the web/API gateway.
 *
 * PI WEB ships no user authentication of its own; historically the whole HTTP
 * and WebSocket surface relied entirely on the network layer (loopback bind +
 * reverse proxy). This guard adds three opt-in-but-safe-by-default protections
 * that close the cross-site-WebSocket / DNS-rebinding chain even before an
 * authenticating reverse proxy is involved:
 *
 * 1. Host-header allowlist (anti DNS-rebinding). Active only when `allowedHosts`
 *    is a list; `true`/undefined keep the previous accept-all behaviour. IP
 *    literals and `localhost` are always accepted (DNS rebinding needs a name).
 * 2. Cross-origin WebSocket rejection. Always on, zero config: a WebSocket
 *    upgrade whose `Origin` host differs from the request `Host` is refused, so
 *    a malicious page cannot hijack a terminal/session socket.
 * 3. Optional shared-secret gate. Active only when `authToken` is set (from the
 *    `PI_WEB_AUTH_TOKEN` environment variable). The secret may be presented as a
 *    Bearer token, an `x-pi-web-token` header, a `pi_web_auth` cookie, or a
 *    one-time `?__auth=` bootstrap query that is exchanged for a `SameSite=Strict`
 *    cookie. The cookie's SameSite attribute also blocks cross-site requests.
 */
export interface RequestGuardOptions {
  /** Host allowlist from config. `true` or `undefined` disables Host filtering. */
  allowedHosts?: string[] | true;
  /** Optional shared secret required on every request. Sourced from PI_WEB_AUTH_TOKEN. */
  authToken?: string;
  /** Path prefixes exempt from the shared-secret requirement (e.g. liveness probes). */
  publicPaths?: string[];
}

const AUTH_COOKIE = "pi_web_auth";
const AUTH_QUERY = "__auth";
const DEFAULT_PUBLIC_PATHS = ["/livez"];

export function createRequestGuard(options: RequestGuardOptions): (request: FastifyRequest, reply: FastifyReply) => Promise<FastifyReply | undefined> {
  const { allowedHosts, authToken } = options;
  const publicPaths = options.publicPaths ?? DEFAULT_PUBLIC_PATHS;
  const authEnabled = authToken !== undefined && authToken !== "";

  return async function requestGuard(request, reply): Promise<FastifyReply | undefined> {
    const hostHeader = headerValue(request.headers.host);

    if (!isHostAllowed(hostHeader, allowedHosts)) {
      return reply.code(403).send({ error: "Host header is not allowed" });
    }

    if (isWebSocketUpgrade(request) && isCrossOriginWebSocket(headerValue(request.headers.origin), hostHeader)) {
      return reply.code(403).send({ error: "Cross-origin WebSocket connections are not allowed" });
    }

    if (!authEnabled) return undefined;

    const url = parseRequestUrl(request.url);
    if (isPublicPath(url.pathname, publicPaths)) return undefined;

    const presented = presentedToken(request, url);
    if (presented === undefined || !tokensMatch(presented, authToken)) {
      return reply.code(401).send({ error: "Authentication required" });
    }

    // Bootstrap: exchange a valid `?__auth=` query for a SameSite cookie so the
    // token is not carried in the URL of every subsequent request or referrer.
    if (url.searchParams.get(AUTH_QUERY) !== null) {
      setAuthCookie(request, reply, presented);
      if (request.method === "GET" || request.method === "HEAD") {
        url.searchParams.delete(AUTH_QUERY);
        const target = `${url.pathname}${url.search}` || "/";
        return reply.code(303).header("location", target).send();
      }
    }

    return undefined;
  };
}

export function isHostAllowed(hostHeader: string | undefined, allowedHosts: string[] | true | undefined): boolean {
  if (allowedHosts === undefined || allowedHosts === true) return true;
  const hostname = hostnameFromHost(hostHeader);
  if (hostname === undefined) return false;
  if (hostname === "localhost" || isIpLiteral(hostname)) return true;
  return allowedHosts.some((allowed) => allowed.trim().toLowerCase() === hostname);
}

export function isWebSocketUpgrade(request: Pick<FastifyRequest, "headers">): boolean {
  return headerValue(request.headers.upgrade)?.toLowerCase() === "websocket";
}

/** Returns true when a WebSocket upgrade should be rejected as cross-origin. */
export function isCrossOriginWebSocket(originHeader: string | undefined, hostHeader: string | undefined): boolean {
  if (originHeader === undefined || originHeader === "") return false; // non-browser client sends no Origin
  const originHost = hostnameFromOrigin(originHeader);
  if (originHost === undefined) return true; // present but unparseable/opaque ("null") -> reject
  return originHost !== hostnameFromHost(hostHeader);
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

function hostnameFromHost(hostHeader: string | undefined): string | undefined {
  if (hostHeader === undefined) return undefined;
  const trimmed = hostHeader.trim();
  if (trimmed === "") return undefined;
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    return end === -1 ? undefined : trimmed.slice(1, end).toLowerCase();
  }
  const [host] = trimmed.split(":");
  return host === undefined || host === "" ? undefined : host.toLowerCase();
}

function hostnameFromOrigin(origin: string): string | undefined {
  if (origin === "null") return undefined;
  try {
    const hostname = new URL(origin).hostname;
    return hostname === "" ? undefined : hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isIpLiteral(hostname: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true; // IPv4
  return hostname.includes(":"); // IPv6 literal (already unbracketed)
}

function parseRequestUrl(requestUrl: string): URL {
  return new URL(requestUrl, "http://pi-web.invalid");
}

function isPublicPath(pathname: string, publicPaths: string[]): boolean {
  return publicPaths.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function presentedToken(request: FastifyRequest, url: URL): string | undefined {
  const authorization = headerValue(request.headers.authorization);
  if (authorization?.startsWith("Bearer ") === true) {
    const token = authorization.slice("Bearer ".length).trim();
    if (token !== "") return token;
  }
  const headerToken = headerValue(request.headers["x-pi-web-token"]);
  if (headerToken !== undefined && headerToken !== "") return headerToken;
  const cookieToken = readCookie(headerValue(request.headers.cookie), AUTH_COOKIE);
  if (cookieToken !== undefined && cookieToken !== "") return cookieToken;
  const queryToken = url.searchParams.get(AUTH_QUERY);
  if (queryToken !== null && queryToken !== "") return queryToken;
  return undefined;
}

function readCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (cookieHeader === undefined) return undefined;
  for (const part of cookieHeader.split(";")) {
    const separator = part.indexOf("=");
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function setAuthCookie(request: FastifyRequest, reply: FastifyReply, token: string): void {
  const secure = headerValue(request.headers["x-forwarded-proto"])?.split(",")[0]?.trim() === "https" || request.protocol === "https";
  const attributes = ["Path=/", "HttpOnly", "SameSite=Strict", ...(secure ? ["Secure"] : [])];
  reply.header("set-cookie", `${AUTH_COOKIE}=${encodeURIComponent(token)}; ${attributes.join("; ")}`);
}

function tokensMatch(presented: string, expected: string): boolean {
  const presentedBytes = Buffer.from(presented);
  const expectedBytes = Buffer.from(expected);
  if (presentedBytes.length !== expectedBytes.length) return false;
  return timingSafeEqual(presentedBytes, expectedBytes);
}
