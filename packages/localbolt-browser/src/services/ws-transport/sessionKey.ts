/**
 * Session-key public key encoding for the daemon HELLO path.
 *
 * The daemon base64-decodes `session-key.publicKey` (RFC 4648) and rejects
 * anything other than 32 bytes:
 * `[INTEROP-2_HELLO_FAIL] public key length N != 32`.
 *
 * tweetnacl-util `encodeBase64` (`toBase64`) walks `arr.length` and `btoa`s
 * those bytes. A 3-element array-like — including the raw wasm-bindgen
 * multi-value return of `generateEphemeralKeyPair`, `[externrefIndex,
 * errIndex, isErr]` — therefore becomes a 4-character string that decodes
 * to 3 bytes. That is the WebTransport failure that leaves the page on
 * "Establishing secure connection". Copy exactly 32 bytes and encode only
 * that copy. Do not send a frame when the key is any other length.
 */

const X25519_PUBLIC_KEY_LEN = 32;
const STANDARD_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Standard base64 length of a 32-byte key, including padding. */
export const SESSION_PUBLIC_KEY_B64_LEN = 44;

function describedLength(value: unknown): string {
  if (value instanceof Uint8Array) return String(value.byteLength);
  if (value !== null && typeof value === 'object' && 'length' in value) {
    const len = (value as { length: unknown }).length;
    if (typeof len === 'number') return String(len);
  }
  return 'unknown';
}

/**
 * Copy an X25519 public key into a fresh 32-byte buffer.
 * Rejects the raw wasm 3-tuple and any other non-32-byte value.
 */
export function copyX25519PublicKey(publicKey: Uint8Array): Uint8Array {
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== X25519_PUBLIC_KEY_LEN) {
    throw new Error(
      `[SESSION_KEY] public key length ${describedLength(publicKey)} != ${X25519_PUBLIC_KEY_LEN}`,
    );
  }
  const copy = new Uint8Array(X25519_PUBLIC_KEY_LEN);
  copy.set(publicKey);
  return copy;
}

/** RFC 4648 standard base64, with padding. Matches the daemon decoder. */
function encodeStandardBase64(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = bytes[i + 1]!;
    const c = bytes[i + 2]!;
    out += STANDARD_B64[a >> 2];
    out += STANDARD_B64[((a & 0x03) << 4) | (b >> 4)];
    out += STANDARD_B64[((b & 0x0f) << 2) | (c >> 6)];
    out += STANDARD_B64[c & 0x3f];
  }
  const remaining = bytes.length - i;
  if (remaining === 1) {
    const a = bytes[i]!;
    out += STANDARD_B64[a >> 2];
    out += STANDARD_B64[(a & 0x03) << 4];
    out += '==';
  } else if (remaining === 2) {
    const a = bytes[i]!;
    const b = bytes[i + 1]!;
    out += STANDARD_B64[a >> 2];
    out += STANDARD_B64[((a & 0x03) << 4) | (b >> 4)];
    out += STANDARD_B64[(b & 0x0f) << 2];
    out += '=';
  }
  return out;
}

/**
 * Encode a session public key for the `{type:"session-key"}` frame.
 * The result always decodes to the same 32 bytes.
 */
export function encodeSessionPublicKey(publicKey: Uint8Array): string {
  const bytes = copyX25519PublicKey(publicKey);
  const encoded = encodeStandardBase64(bytes);
  if (encoded.length !== SESSION_PUBLIC_KEY_B64_LEN) {
    throw new Error(
      `[SESSION_KEY] public key base64 length ${encoded.length} != ${SESSION_PUBLIC_KEY_B64_LEN}`,
    );
  }
  return encoded;
}
