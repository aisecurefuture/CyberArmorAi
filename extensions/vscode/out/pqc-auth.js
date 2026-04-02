"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildAuthHeaderResult = buildAuthHeaderResult;
exports.buildAuthHeaderValue = buildAuthHeaderValue;
const crypto_1 = require("crypto");
const mlkem_1 = require("mlkem");
const PUBLIC_KEY_CACHE = new Map();
const HEADER_CACHE = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;
function bytesToBase64(bytes) {
    return Buffer.from(bytes).toString("base64");
}
function hexToBytes(hex) {
    return new Uint8Array(Buffer.from(hex, "hex"));
}
function concatBytes(parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
function uint32be(value) {
    const buf = Buffer.alloc(4);
    buf.writeUInt32BE(value, 0);
    return new Uint8Array(buf);
}
function resolvePublicKeyUrl(baseUrl) {
    const parsed = new URL(baseUrl.trim());
    parsed.pathname = "/pki/public-key";
    parsed.search = "";
    parsed.hash = "";
    return parsed.toString();
}
async function fetchPublicKeyInfo(baseUrl) {
    const url = resolvePublicKeyUrl(baseUrl);
    const cached = PUBLIC_KEY_CACHE.get(url);
    if (cached && cached.expiresAt > Date.now())
        return cached.info;
    const response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
    });
    if (!response.ok) {
        throw new Error(`Public key fetch failed: HTTP ${response.status}`);
    }
    const info = (await response.json());
    PUBLIC_KEY_CACHE.set(url, { info, expiresAt: Date.now() + CACHE_TTL_MS });
    return info;
}
async function encryptMlKemHeader(apiKey, publicKeyHex) {
    const kem = new mlkem_1.MlKem1024();
    const [ciphertext, sharedSecret] = await kem.encap(hexToBytes(publicKeyHex));
    const iv = crypto_1.webcrypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto_1.webcrypto.subtle.importKey("raw", new Uint8Array(sharedSecret), { name: "AES-GCM" }, false, ["encrypt"]);
    const encrypted = new Uint8Array(await crypto_1.webcrypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(apiKey)));
    const tag = encrypted.slice(encrypted.length - 16);
    const payload = concatBytes([
        uint32be(ciphertext.length),
        new Uint8Array(ciphertext),
        iv,
        encrypted.slice(0, encrypted.length - 16),
        tag,
    ]);
    return `PQC:${bytesToBase64(payload)}`;
}
async function encryptX25519Header(apiKey, publicKeyHex) {
    const subtle = crypto_1.webcrypto.subtle;
    const serverPublicKey = hexToBytes(publicKeyHex);
    if (serverPublicKey.length !== 32) {
        throw new Error("Unsupported PQC algorithm for VS Code helper");
    }
    const ephemeral = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const rawEphemeralPublic = new Uint8Array(await subtle.exportKey("raw", ephemeral.publicKey));
    const importedServerPublic = await subtle.importKey("raw", serverPublicKey, { name: "X25519" }, false, []);
    const rawShared = await subtle.deriveBits({ name: "X25519", public: importedServerPublic }, ephemeral.privateKey, 256);
    const hkdfKey = await subtle.importKey("raw", rawShared, "HKDF", false, ["deriveBits"]);
    const sharedSecret = new Uint8Array(await subtle.deriveBits({
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(0),
        info: new TextEncoder().encode("cyberarmor-kem-v1"),
    }, hkdfKey, 256));
    const iv = crypto_1.webcrypto.getRandomValues(new Uint8Array(12));
    const aesKey = await subtle.importKey("raw", sharedSecret, { name: "AES-GCM" }, false, ["encrypt"]);
    const encrypted = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(apiKey)));
    const tag = encrypted.slice(encrypted.length - 16);
    const ciphertext = encrypted.slice(0, encrypted.length - 16);
    const payload = concatBytes([
        uint32be(rawEphemeralPublic.length),
        rawEphemeralPublic,
        iv,
        ciphertext,
        tag,
    ]);
    return `PQC:${bytesToBase64(payload)}`;
}
async function buildAuthHeaderResult(baseUrl, apiKey, strict = false) {
    if (!apiKey)
        return { value: "", mode: "missing", algorithm: "none" };
    if (apiKey.startsWith("PQC:"))
        return { value: apiKey, mode: "precomputed_pqc", algorithm: "precomputed" };
    try {
        const info = await fetchPublicKeyInfo(baseUrl);
        const publicKeyHex = info.kem_public_key;
        if (!publicKeyHex)
            throw new Error("Missing kem_public_key");
        const algorithmName = String(info.algorithm || "").toUpperCase();
        const cacheKey = `${baseUrl}::${algorithmName}::${publicKeyHex}::${apiKey}`;
        const cached = HEADER_CACHE.get(cacheKey);
        if (cached && cached.expiresAt > Date.now())
            return { value: cached.value, mode: algorithmName.includes("ML-KEM-1024") ? "native_ml_kem" : "x25519_fallback", algorithm: algorithmName, cached: true };
        const value = algorithmName.includes("ML-KEM-1024")
            ? await encryptMlKemHeader(apiKey, publicKeyHex)
            : await encryptX25519Header(apiKey, publicKeyHex);
        HEADER_CACHE.set(cacheKey, { value, expiresAt: Date.now() + CACHE_TTL_MS });
        return {
            value,
            mode: algorithmName.includes("ML-KEM-1024") ? "native_ml_kem" : "x25519_fallback",
            algorithm: algorithmName || "unknown",
            cached: false,
        };
    }
    catch (error) {
        if (strict)
            throw error;
        return {
            value: apiKey,
            mode: "plaintext_fallback",
            algorithm: "fallback",
            error: error instanceof Error ? error.message : String(error),
        };
    }
}
async function buildAuthHeaderValue(baseUrl, apiKey, strict = false) {
    const result = await buildAuthHeaderResult(baseUrl, apiKey, strict);
    return result.value;
}
//# sourceMappingURL=pqc-auth.js.map