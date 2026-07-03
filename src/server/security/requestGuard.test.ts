import Fastify, { type FastifyInstance } from "fastify";
import { afterEach, describe, expect, it } from "vitest";
import { createRequestGuard, isCrossOriginWebSocket, isHostAllowed, isWebSocketUpgrade, type RequestGuardOptions } from "./requestGuard.js";

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function buildGuardedApp(options: RequestGuardOptions): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false });
  instance.addHook("onRequest", createRequestGuard(options));
  instance.get("/livez", () => ({ ok: true }));
  instance.get("/thing", () => ({ ok: true }));
  instance.post("/thing", () => ({ ok: true }));
  app = instance;
  return instance;
}

describe("isHostAllowed", () => {
  it("allows any host when no allowlist is configured", () => {
    expect(isHostAllowed("evil.example", undefined)).toBe(true);
    expect(isHostAllowed("evil.example", true)).toBe(true);
  });

  it("accepts configured hostnames case-insensitively and ignores the port", () => {
    expect(isHostAllowed("pi-web.example:8504", ["pi-web.example"])).toBe(true);
    expect(isHostAllowed("PI-WEB.EXAMPLE", ["pi-web.example"])).toBe(true);
  });

  it("rejects hostnames outside the allowlist (DNS-rebinding names)", () => {
    expect(isHostAllowed("attacker.example", ["pi-web.example"])).toBe(false);
    expect(isHostAllowed(undefined, ["pi-web.example"])).toBe(false);
  });

  it("always accepts loopback names and IP literals", () => {
    expect(isHostAllowed("localhost:8504", ["pi-web.example"])).toBe(true);
    expect(isHostAllowed("127.0.0.1:8504", ["pi-web.example"])).toBe(true);
    expect(isHostAllowed("[::1]:8504", ["pi-web.example"])).toBe(true);
  });
});

describe("isCrossOriginWebSocket", () => {
  it("allows upgrades with no Origin (non-browser clients)", () => {
    expect(isCrossOriginWebSocket(undefined, "pi-web.example")).toBe(false);
  });

  it("allows same-host Origins regardless of scheme or port", () => {
    expect(isCrossOriginWebSocket("https://pi-web.example", "pi-web.example")).toBe(false);
    expect(isCrossOriginWebSocket("http://pi-web.example:8504", "pi-web.example")).toBe(false);
  });

  it("rejects different-host and opaque Origins", () => {
    expect(isCrossOriginWebSocket("https://attacker.example", "pi-web.example")).toBe(true);
    expect(isCrossOriginWebSocket("null", "pi-web.example")).toBe(true);
    expect(isCrossOriginWebSocket("not-a-url", "pi-web.example")).toBe(true);
  });
});

describe("isWebSocketUpgrade", () => {
  it("detects websocket upgrade requests case-insensitively", () => {
    expect(isWebSocketUpgrade({ headers: { upgrade: "WebSocket" } })).toBe(true);
    expect(isWebSocketUpgrade({ headers: {} })).toBe(false);
  });
});

describe("request guard hook", () => {
  it("passes requests through when nothing is configured", async () => {
    const instance = await buildGuardedApp({});
    const response = await instance.inject({ method: "GET", url: "/thing", headers: { host: "anything.example" } });
    expect(response.statusCode).toBe(200);
  });

  it("blocks disallowed Host headers with 403", async () => {
    const instance = await buildGuardedApp({ allowedHosts: ["pi-web.example"] });
    const blocked = await instance.inject({ method: "GET", url: "/thing", headers: { host: "attacker.example" } });
    const allowed = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example" } });
    expect(blocked.statusCode).toBe(403);
    expect(allowed.statusCode).toBe(200);
  });

  it("rejects cross-origin WebSocket upgrades but allows same-origin ones", async () => {
    const instance = await buildGuardedApp({});
    const crossOrigin = await instance.inject({
      method: "GET",
      url: "/thing",
      headers: { host: "pi-web.example", upgrade: "websocket", connection: "upgrade", origin: "https://attacker.example" },
    });
    const sameOrigin = await instance.inject({
      method: "GET",
      url: "/thing",
      headers: { host: "pi-web.example", upgrade: "websocket", connection: "upgrade", origin: "https://pi-web.example" },
    });
    expect(crossOrigin.statusCode).toBe(403);
    expect(sameOrigin.statusCode).toBe(200);
  });

  it("does not apply the Origin check to non-WebSocket requests", async () => {
    const instance = await buildGuardedApp({});
    const response = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example", origin: "https://attacker.example" } });
    expect(response.statusCode).toBe(200);
  });

  it("requires the shared secret when configured", async () => {
    const instance = await buildGuardedApp({ authToken: "s3cret" });
    const missing = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example" } });
    const wrong = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example", authorization: "Bearer nope" } });
    const bearer = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example", authorization: "Bearer s3cret" } });
    const headerToken = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example", "x-pi-web-token": "s3cret" } });
    const cookie = await instance.inject({ method: "GET", url: "/thing", headers: { host: "pi-web.example", cookie: "pi_web_auth=s3cret" } });
    expect(missing.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    expect(bearer.statusCode).toBe(200);
    expect(headerToken.statusCode).toBe(200);
    expect(cookie.statusCode).toBe(200);
  });

  it("exchanges a valid bootstrap query for a SameSite cookie and strips the token from the URL", async () => {
    const instance = await buildGuardedApp({ authToken: "s3cret" });
    const response = await instance.inject({ method: "GET", url: "/thing?__auth=s3cret&keep=1", headers: { host: "pi-web.example", "x-forwarded-proto": "https" } });
    expect(response.statusCode).toBe(303);
    expect(response.headers.location).toBe("/thing?keep=1");
    const setCookie = response.headers["set-cookie"];
    expect(setCookie).toContain("pi_web_auth=s3cret");
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).toContain("Secure");
  });

  it("omits the Secure attribute for plain-HTTP bootstrap so local access still works", async () => {
    const instance = await buildGuardedApp({ authToken: "s3cret" });
    const response = await instance.inject({ method: "POST", url: "/thing?__auth=s3cret", headers: { host: "127.0.0.1:8504" } });
    expect(response.statusCode).toBe(200);
    expect(response.headers["set-cookie"]).not.toContain("Secure");
  });

  it("leaves public liveness paths reachable without the shared secret", async () => {
    const instance = await buildGuardedApp({ authToken: "s3cret" });
    const response = await instance.inject({ method: "GET", url: "/livez", headers: { host: "127.0.0.1:8504" } });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ok: true });
  });
});
