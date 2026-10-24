// @vitest-environment node
/**
 * Session-key publicKey on the WebTransport HELLO path.
 *
 * The daemon rejects a session key whose standard-base64 form decodes to
 * anything other than 32 bytes (`public key length N != 32`). tweetnacl
 * `toBase64` encodes a 3-element array-like — the raw wasm-bindgen return
 * of generateEphemeralKeyPair — as a 4-character string that hits that error.
 */
import { readFileSync } from 'node:fs';
import { describe, it, expect, afterEach } from 'vitest';
import { fromBase64, generateEphemeralKeyPair, initWasmCryptoFromModule, toBase64 } from '@the9ines/bolt-core';
import * as wasm from '../../wasm/bolt_protocol_wasm.js';
import { WtDataTransport } from '../services/ws-transport/WtDataTransport.js';
import {
  encodeSessionPublicKey,
  SESSION_PUBLIC_KEY_B64_LEN,
} from '../services/ws-transport/sessionKey.js';

const WASM_TUPLE = [2, 0, 0];

function decodeStandardBase64(b64: string): Buffer {
  return Buffer.from(b64, 'base64');
}

describe('encodeSessionPublicKey', () => {
  it('matches RFC 4648 and round-trips 32 bytes, including a byteOffset view', () => {
    const key = new Uint8Array(32);
    for (let i = 0; i < key.length; i++) key[i] = (i * 7 + 3) & 0xff;
    const encoded = encodeSessionPublicKey(key);
    expect(encoded).toBe(Buffer.from(key).toString('base64'));
    expect(encoded.length).toBe(SESSION_PUBLIC_KEY_B64_LEN);
    expect(decodeStandardBase64(encoded)).toEqual(Buffer.from(key));
    expect(fromBase64(encoded)).toEqual(key);

    const backing = new Uint8Array(80);
    backing.set(key, 17);
    const view = backing.subarray(17, 49);
    expect(view.byteOffset).not.toBe(0);
    expect(view.byteLength).toBe(32);
    expect(encodeSessionPublicKey(view)).toBe(encoded);
  });

  it('does not emit the length-3 key that the daemon rejects', () => {
    const three = Uint8Array.of(1, 2, 3);
    // The old encoder turns this into AQID, which decodes to 3 bytes.
    const legacy = toBase64(three);
    expect(legacy).toBe('AQID');
    expect(fromBase64(legacy).length).toBe(3);

    expect(() => encodeSessionPublicKey(three)).toThrow(/public key length 3 != 32/);
    expect(() => encodeSessionPublicKey(WASM_TUPLE as unknown as Uint8Array)).toThrow(
      /public key length 3 != 32/,
    );
    // The raw wasm multi-value is itself a 3-element array-like. toBase64 of
    // it is a valid short key; the session-key encoder must not produce one.
    const tupleB64 = toBase64(WASM_TUPLE as unknown as Uint8Array);
    expect(fromBase64(tupleB64).length).toBe(3);
  });
});

describe('WtDataTransport WASM session-key frame', () => {
  let writerChunks: Uint8Array[] = [];

  afterEach(() => {
    delete (globalThis as any).WebTransport;
    writerChunks = [];
  });

  it('sends a 32-byte publicKey from the real protocol WASM keypair', async () => {
    const wasmBytes = readFileSync(new URL('../../wasm/bolt_protocol_wasm_bg.wasm', import.meta.url));
    await wasm.default({ module_or_path: wasmBytes });
    expect(initWasmCryptoFromModule(wasm)).toBe(true);

    const probed = generateEphemeralKeyPair();
    expect(probed.publicKey).toBeInstanceOf(Uint8Array);
    expect(probed.publicKey.byteLength).toBe(32);
    expect(probed.secretKey.byteLength).toBe(32);

    writerChunks = [];
    (globalThis as any).WebTransport = class {
      ready: Promise<void>;
      closed: Promise<void>;
      constructor(public url: string, public options: unknown) {
        this.ready = Promise.resolve();
        this.closed = new Promise(() => {});
      }
      async createBidirectionalStream() {
        return {
          writable: {
            getWriter: () => ({
              write: async (data: Uint8Array) => {
                writerChunks.push(data);
              },
              close: async () => {},
            }),
          },
          readable: {
            getReader: () => ({
              read: () => new Promise(() => {}),
              releaseLock: () => {},
            }),
          },
        };
      }
      close() {}
    };

    const transport = new WtDataTransport({
      daemonUrl: 'https://192.168.4.25:4433',
      certHashHex: 'ab'.repeat(32),
      connectTimeout: 150,
    });
    const connectPromise = transport.connect();
    const publicKey = (transport as any).keyPair.publicKey as Uint8Array;
    await new Promise((r) => setTimeout(r, 20));

    expect(writerChunks.length).toBeGreaterThan(0);
    const frame = writerChunks[0]!;
    const view = new DataView(frame.buffer, frame.byteOffset, 4);
    const len = view.getUint32(0, false);
    const msg = JSON.parse(new TextDecoder().decode(frame.subarray(4, 4 + len))) as {
      type: string;
      publicKey: string;
    };
    expect(msg.type).toBe('session-key');
    expect(msg.publicKey.length).toBe(SESSION_PUBLIC_KEY_B64_LEN);
    const decoded = decodeStandardBase64(msg.publicKey);
    expect(decoded.length).toBe(32);
    expect(new Uint8Array(decoded)).toEqual(publicKey);

    transport.disconnect();
    await connectPromise;
  });
});
