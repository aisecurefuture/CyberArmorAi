import { MlKem1024 } from "mlkem";

(function attachPqcAuth(global) {
  "use strict";

  const PUBLIC_KEY_CACHE = new Map();
  const HEADER_CACHE = new Map();
  const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
  const HKDF_INFO = new TextEncoder().encode("cyberarmor-kem-v1");

  let x25519SupportPromise = null;

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function hexToBytes(hex) {
    if (!hex || typeof hex !== "string" || hex.length % 2 !== 0) {
      throw new Error("Invalid hex public key");
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    return out;
  }

  function concatBytes() {
    const parts = Array.from(arguments);
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  function toBigEndianUint32(value) {
    const buf = new ArrayBuffer(4);
    new DataView(buf).setUint32(0, value, false);
    return new Uint8Array(buf);
  }

  function resolvePublicKeyUrl(baseUrl) {
    const parsed = new URL(String(baseUrl || "").trim());
    parsed.pathname = "/pki/public-key";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
  }

  async function supportsX25519() {
    if (!global.crypto || !global.crypto.subtle) return false;
    if (!x25519SupportPromise) {
      x25519SupportPromise = global.crypto.subtle.generateKey(
        { name: "X25519" },
        true,
        ["deriveBits"]
      ).then(() => true).catch(() => false);
    }
    return x25519SupportPromise;
  }

  async function fetchPublicKeyInfo(baseUrl, timeoutMs) {
    const publicKeyUrl = resolvePublicKeyUrl(baseUrl);
    const cached = PUBLIC_KEY_CACHE.get(publicKeyUrl);
    if (cached && cached.expiresAt > Date.now()) return cached.info;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(publicKeyUrl, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Public key fetch failed: HTTP ${response.status}`);
      const info = await response.json();
      PUBLIC_KEY_CACHE.set(publicKeyUrl, {
        info,
        expiresAt: Date.now() + DEFAULT_CACHE_TTL_MS,
      });
      return info;
    } finally {
      clearTimeout(timer);
    }
  }

  async function deriveX25519SharedSecret(serverPublicKeyBytes) {
    const subtle = global.crypto.subtle;
    const ephemeral = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const rawEphemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
    const importedServerPublic = await subtle.importKey(
      "raw",
      serverPublicKeyBytes,
      { name: "X25519" },
      false,
      []
    );
    const rawShared = await subtle.deriveBits(
      { name: "X25519", public: importedServerPublic },
      ephemeral.privateKey,
      256
    );
    const hkdfKey = await subtle.importKey("raw", rawShared, "HKDF", false, ["deriveBits"]);
    const sharedSecret = new Uint8Array(await subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: HKDF_INFO,
      },
      hkdfKey,
      256
    ));
    return { ciphertext: rawEphemeralPublic, sharedSecret };
  }

  async function deriveMlKemSharedSecret(serverPublicKeyBytes) {
    const kem = new MlKem1024();
    const [ciphertext, sharedSecret] = await kem.encap(serverPublicKeyBytes);
    return {
      ciphertext: new Uint8Array(ciphertext),
      sharedSecret: new Uint8Array(sharedSecret),
    };
  }

  async function encryptTransportPayload(apiKey, kemCiphertext, sharedSecret) {
    const subtle = global.crypto.subtle;
    const iv = global.crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await subtle.importKey("raw", sharedSecret, { name: "AES-GCM" }, false, ["encrypt"]);
    const plaintext = new TextEncoder().encode(apiKey);
    const encrypted = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext));
    const tag = encrypted.slice(encrypted.length - 16);
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const payload = concatBytes(
      toBigEndianUint32(kemCiphertext.length),
      kemCiphertext,
      iv,
      ciphertext,
      tag
    );
    return `PQC:${bytesToBase64(payload)}`;
  }

  async function encryptMlKemHeader(apiKey, publicKeyHex) {
    const serverPublicKeyBytes = hexToBytes(publicKeyHex);
    const derived = await deriveMlKemSharedSecret(serverPublicKeyBytes);
    return encryptTransportPayload(apiKey, derived.ciphertext, derived.sharedSecret);
  }

  async function encryptX25519Header(apiKey, publicKeyHex) {
    const serverPublicKeyBytes = hexToBytes(publicKeyHex);
    if (serverPublicKeyBytes.length !== 32) {
      throw new Error("Unsupported X25519 public key");
    }
    const derived = await deriveX25519SharedSecret(serverPublicKeyBytes);
    return encryptTransportPayload(apiKey, derived.ciphertext, derived.sharedSecret);
  }

  async function getAuthHeaderValue(options) {
    const result = await getAuthHeaderResult(options);
    return result.value;
  }

  async function getAuthHeaderResult(options) {
    const apiKey = options && typeof options.apiKey === "string" ? options.apiKey : "";
    if (!apiKey) return { value: "", mode: "missing", algorithm: "none" };
    if (apiKey.startsWith("PQC:")) {
      return { value: apiKey, mode: "precomputed_pqc", algorithm: "precomputed" };
    }
    if (options?.pqcEnabled === false) {
      return { value: apiKey, mode: "plaintext_fallback", algorithm: "disabled" };
    }

    const strict = options?.strict === true;
    const baseUrl = options?.baseUrl || options?.controlPlaneUrl;
    if (!baseUrl) return { value: apiKey, mode: "plaintext_fallback", algorithm: "no_base_url" };

    try {
      const info = await fetchPublicKeyInfo(baseUrl, options?.timeoutMs || 3000);
      const publicKeyHex = info?.kem_public_key;
      if (!publicKeyHex) throw new Error("Missing kem_public_key");
      const algorithm = String(info?.algorithm || "").toUpperCase();
      const cacheKey = `${baseUrl}::${algorithm}::${publicKeyHex}::${apiKey}`;
      const cachedHeader = HEADER_CACHE.get(cacheKey);
      if (cachedHeader && cachedHeader.expiresAt > Date.now()) {
        return { ...cachedHeader.info, cached: true };
      }

      let value;
      let mode;
      if (algorithm.includes("ML-KEM-1024")) {
        value = await encryptMlKemHeader(apiKey, publicKeyHex);
        mode = "native_ml_kem";
      } else {
        if (!(await supportsX25519())) throw new Error("X25519 Web Crypto support unavailable");
        value = await encryptX25519Header(apiKey, publicKeyHex);
        mode = "x25519_fallback";
      }

      const infoRecord = { value, mode, algorithm: algorithm || "unknown", cached: false };
      HEADER_CACHE.set(cacheKey, {
        info: infoRecord,
        expiresAt: Date.now() + (options?.cacheTtlMs || DEFAULT_CACHE_TTL_MS),
      });
      return infoRecord;
    } catch (error) {
      if (strict) throw error;
      return {
        value: apiKey,
        mode: "plaintext_fallback",
        algorithm: "fallback",
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  async function buildHeaders(options) {
    const headers = { ...(options?.headers || {}) };
    const result = await getAuthHeaderResult(options);
    if (result.value) headers["x-api-key"] = result.value;
    return { headers, authInfo: result };
  }

  global.CyberArmorPQCAuth = {
    getAuthHeaderValue,
    getAuthHeaderResult,
    buildHeaders,
  };
})(typeof self !== "undefined" ? self : window);
