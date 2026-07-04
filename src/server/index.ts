#!/usr/bin/env node
import { effectivePiWebConfig, maxUploadBytes } from "../config.js";
import { buildApp } from "./app.js";

const { config } = effectivePiWebConfig();
const authToken = process.env["PI_WEB_AUTH_TOKEN"];
const app = await buildApp({
  bodyLimit: maxUploadBytes(process.env, config),
  security: {
    ...(config.allowedHosts !== undefined ? { allowedHosts: config.allowedHosts } : {}),
    ...(authToken !== undefined && authToken !== "" ? { authToken } : {}),
  },
});
await app.listen({ port: config.port ?? 8504, host: config.host ?? "127.0.0.1" });
