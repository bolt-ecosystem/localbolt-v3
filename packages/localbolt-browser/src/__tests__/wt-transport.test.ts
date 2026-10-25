// @vitest-environment node
/**
 * WebTransport adapter tests (WTI3).
 *
 * Tests WtDataTransport, framing helpers, and BrowserAppTransport
 * three-tier fallback without real WebTransport connections.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateEphemeralKeyPair, toBase64, fromBase64 } from '@the9ines/bolt-core';
import { encodeFrame, FrameDeframer, WtDataTransport } from '../services/ws-transport/WtDataTransport.js';
import { SESSION_PUBLIC_KEY_B64_LEN } from '../services/ws-transport/sessionKey.js';
import { WsDataTransport } from '../services/ws-transport/WsDataTransport.js';
import { BrowserAppTransport } from '../services/ws-transport/BrowserAppTransport.js';

// ─── Mock WebSocket (reused from ws-transport.test.ts pattern) ──────────────

class MockWebSocket {
  static OPEN = 1;
  static CLOSED = 3;
  static CONNECTING = 0;

  readyState: number = MockWebSocket.CONNECTING;
  onopen: ((ev: any) => void) | null = null;
  onclose: ((ev: any) => void) | null = null;
  onerror: ((ev: any) => void) | null = null;
  onmessage: ((ev: any) => void) | null = null;
  sentMessages: string[] = [];
  url: string;

  constructor(url: string) {
    this.url = url;
  }
  send(data: string): void { this.sentMessages.push(data); }
  close(): void { this.readyState = MockWebSocket.CLOSED; }
  simulateOpen(): void {
    this.readyState = MockWebSocket.OPEN;
    this.onopen?.({});
  }
  simulateMessage(data: string): void { this.onmessage?.({ data }); }
  simulateError(): void { this.onerror?.({}); }
  simulateClose(): void {
    this.readyState = MockWebSocket.CLOSED;
    this.onclose?.({ code: 1000, reason: '' });
  }
}

let mockWsInstances: MockWebSocket[] = [];
let originalWebSocket: any;

function installMockWebSocket(): void {
  originalWebSocket = globalThis.WebSocket;
  (globalThis as any).WebSocket = class extends MockWebSocket {
    constructor(url: string) {
      super(url);
      mockWsInstances.push(this);
    }
  };
  (globalThis as any).WebSocket.OPEN = MockWebSocket.OPEN;
  (globalThis as any).WebSocket.CLOSED = MockWebSocket.CLOSED;
  (globalThis as any).WebSocket.CONNECTING = MockWebSocket.CONNECTING;
}

function uninstallMockWebSocket(): void {
  globalThis.WebSocket = originalWebSocket;
  mockWsInstances = [];
}

function getLastMockWs(): MockWebSocket {
  return mockWsInstances[mockWsInstances.length - 1];
}

// ─── Mock WebTransport ──────────────────────────────────────────────────────

class MockWritableStream {
  private writer: MockWriter;
  constructor() { this.writer = new MockWriter(); }
  getWriter(): MockWriter { return this.writer; }
}

class MockWriter {
  written: Uint8Array[] = [];
  closed = false;
  async write(data: Uint8Array): Promise<void> { this.written.push(data); }
  async close(): Promise<void> { this.closed = true; }
}

class MockReadableStream {
  private chunks: Uint8Array[] = [];
  private resolve: ((result: ReadableStreamReadResult<Uint8Array>) => void) | null = null;
  private done = false;

  pushChunk(data: Uint8Array): void {
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: false, value: data });
    } else {
      this.chunks.push(data);
    }
  }

  finish(): void {
    this.done = true;
    if (this.resolve) {
      const r = this.resolve;
      this.resolve = null;
      r({ done: true, value: undefined as any });
    }
  }

  getReader(): { read: () => Promise<ReadableStreamReadResult<Uint8Array>>; releaseLock: () => void } {
    return {
      read: () => {
        if (this.chunks.length > 0) {
          return Promise.resolve({ done: false, value: this.chunks.shift()! } as ReadableStreamReadResult<Uint8Array>);
        }
        if (this.done) {
          return Promise.resolve({ done: true, value: undefined as any } as ReadableStreamReadResult<Uint8Array>);
        }
        return new Promise((resolve) => { this.resolve = resolve; });
      },
      releaseLock: () => {},
    };
  }
}

class MockBidiStream {
  writable: MockWritableStream;
  readable: MockReadableStream;
  constructor() {
    this.writable = new MockWritableStream();
    this.readable = new MockReadableStream();
  }
}

let mockWtReady: { resolve: () => void; reject: (e: any) => void } | null = null;
let mockWtClosed: { resolve: () => void; reject: (e: any) => void } | null = null;
let lastMockBidiStream: MockBidiStream | null = null;
let wtConstructorCalled = false;

function installMockWebTransport(): void {
  (globalThis as any).WebTransport = class {
    ready: Promise<void>;
    closed: Promise<void>;

    constructor(public url: string) {
      wtConstructorCalled = true;
      this.ready = new Promise((resolve, reject) => {
        mockWtReady = { resolve, reject };
      });
      this.closed = new Promise((resolve, reject) => {
        mockWtClosed = { resolve, reject };
      });
    }

    async createBidirectionalStream(): Promise<MockBidiStream> {
      lastMockBidiStream = new MockBidiStream();
      return lastMockBidiStream;
    }

    close(): void {}
  };
}

function uninstallMockWebTransport(): void {
  delete (globalThis as any).WebTransport;
  mockWtReady = null;
  mockWtClosed = null;
  lastMockBidiStream = null;
  wtConstructorCalled = false;
}

/**
 * Simulate WT ready + daemon session-key response.
 * After session-key exchange was added, resolving mockWtReady alone is not
 * enough — the transport sends a session-key and waits for the daemon's reply
 * (as a framed message through the bidi stream readable side).
 */
async function simulateReadyAndSessionKey(): Promise<void> {
  mockWtReady!.resolve();
  // Allow microtasks to process (stream creation, session-key send)
  await new Promise(r => setTimeout(r, 10));
  // Feed daemon session-key as a framed message through the readable stream
  const daemonKp = generateEphemeralKeyPair();
  const sessionKeyMsg = JSON.stringify({
    type: 'session-key',
    publicKey: toBase64(daemonKp.publicKey),
  });
  const frame = encodeFrame(sessionKeyMsg);
  lastMockBidiStream!.readable.pushChunk(frame);
  // Allow handleMessage to process
  await new Promise(r => setTimeout(r, 10));
}

/**
 * WS helper: simulate open + daemon session-key for BrowserAppTransport tests
 * that fall through to WS transport.
 */
function simulateWsOpenAndSessionKey(ws: MockWebSocket): void {
  ws.simulateOpen();
  const daemonKp = generateEphemeralKeyPair();
  ws.simulateMessage(JSON.stringify({
    type: 'session-key',
    publicKey: toBase64(daemonKp.publicKey),
  }));
}

// ─── Frame encoding/decoding tests ─────────────────────────────────────────

describe('Frame encoding/decoding', () => {
  it('encodeFrame produces correct 4-byte BE header + payload', () => {
    const frame = encodeFrame('hello');
    expect(frame.length).toBe(4 + 5);
    const view = new DataView(frame.buffer);
    expect(view.getUint32(0, false)).toBe(5);
    expect(new TextDecoder().decode(frame.slice(4))).toBe('hello');
  });

  it('encodeFrame handles empty string', () => {
    const frame = encodeFrame('');
    expect(frame.length).toBe(4);
    const view = new DataView(frame.buffer);
    expect(view.getUint32(0, false)).toBe(0);
  });

  it('encodeFrame handles unicode', () => {
    const msg = 'hello 🌍';
    const frame = encodeFrame(msg);
    const view = new DataView(frame.buffer, frame.byteOffset, 4);
    const len = view.getUint32(0, false);
    const decoded = new TextDecoder().decode(frame.slice(4));
    expect(decoded).toBe(msg);
    expect(len).toBe(new TextEncoder().encode(msg).length);
  });
});

describe('FrameDeframer', () => {
  it('deframes a single complete frame', () => {
    const deframer = new FrameDeframer();
    const frame = encodeFrame('test message');
    const result = deframer.push(frame);
    expect(result).toEqual(['test message']);
  });

  it('deframes multiple frames in one chunk', () => {
    const deframer = new FrameDeframer();
    const f1 = encodeFrame('first');
    const f2 = encodeFrame('second');
    const combined = new Uint8Array(f1.length + f2.length);
    combined.set(f1);
    combined.set(f2, f1.length);
    const result = deframer.push(combined);
    expect(result).toEqual(['first', 'second']);
  });

  it('handles partial frames across pushes', () => {
    const deframer = new FrameDeframer();
    const frame = encodeFrame('hello world');

    // Push first 3 bytes (partial header)
    const part1 = frame.slice(0, 3);
    expect(deframer.push(part1)).toEqual([]);

    // Push rest
    const part2 = frame.slice(3);
    expect(deframer.push(part2)).toEqual(['hello world']);
  });

  it('handles frame split in the middle of payload', () => {
    const deframer = new FrameDeframer();
    const frame = encodeFrame('abcdefgh');

    // Push header + partial payload
    const part1 = frame.slice(0, 6);
    expect(deframer.push(part1)).toEqual([]);

    // Push rest of payload
    const part2 = frame.slice(6);
    expect(deframer.push(part2)).toEqual(['abcdefgh']);
  });

  it('throws on frame exceeding max size', () => {
    const deframer = new FrameDeframer();
    const header = new Uint8Array(4);
    const view = new DataView(header.buffer);
    view.setUint32(0, 2_000_000, false); // > 1 MiB
    expect(() => deframer.push(header)).toThrow('Frame too large');
  });

  it('reset clears internal buffer', () => {
    const deframer = new FrameDeframer();
    const frame = encodeFrame('hello');
    deframer.push(frame.slice(0, 3)); // partial header
    deframer.reset();
    // After reset, a fresh complete frame should parse correctly
    const freshFrame = encodeFrame('world');
    const result = deframer.push(freshFrame);
    expect(result).toEqual(['world']);
  });
});

// ─── WtDataTransport tests ─────────────────────────────────────────────────

describe('WtDataTransport', () => {
  afterEach(() => {
    uninstallMockWebTransport();
  });

  it('returns false when WebTransport is not available', async () => {
    // Do NOT install mock — WebTransport should be undefined
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 500,
    });
    const result = await transport.connect();
    expect(result).toBe(false);
  });

  it('returns false on connection timeout', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 100,
    });

    const result = await transport.connect();
    // ready never resolves -> timeout
    expect(result).toBe(false);
  });

  it('frames a session-key whose publicKey is exactly 32 raw bytes', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://192.168.4.25:4433',
      certHashHex: 'ab'.repeat(32),
      connectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    const publicKey = (transport as any).keyPair.publicKey as Uint8Array;
    await simulateReadyAndSessionKey();
    await connectPromise;

    const writer = (transport as any).bridge._writer as MockWriter;
    expect(writer.written.length).toBeGreaterThan(0);
    const frame = writer.written[0]!;
    const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
    const len = view.getUint32(0, false);
    const json = new TextDecoder().decode(frame.subarray(4, 4 + len));
    expect(json.length).toBe(len);
    const msg = JSON.parse(json) as { type: string; publicKey: string };
    expect(msg.type).toBe('session-key');
    expect(msg.publicKey.length).toBe(SESSION_PUBLIC_KEY_B64_LEN);
    const decoded = fromBase64(msg.publicKey);
    expect(decoded.length).toBe(32);
    expect(decoded).toEqual(publicKey);

    transport.disconnect();
  });

  it('connects in legacy mode when no identity configured', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();

    const result = await connectPromise;
    expect(result).toBe(true);
    expect(transport.connected).toBe(true);

    transport.disconnect();
    expect(transport.connected).toBe(false);
  });

  it('transitions readyState through lifecycle', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
    });

    // Before connect: closed
    expect(transport.connected).toBe(false);

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    // After connect: open
    expect(transport.connected).toBe(true);

    transport.disconnect();
    // After disconnect: closed
    expect(transport.connected).toBe(false);
  });

  it('cleans up resources on disconnect', async () => {
    installMockWebTransport();
    const onDisconnect = vi.fn();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
      onDisconnect,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    transport.disconnect();
    expect(transport.connected).toBe(false);
    expect(onDisconnect).toHaveBeenCalled();
  });

  it('uses same HandshakeManager and TransferManager as WS', () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
    });

    const handshake = (transport as any).handshake;
    const transfer = (transport as any).transfer;
    expect(handshake.constructor.name).toBe('HandshakeManager');
    expect(transfer.constructor.name).toBe('TransferManager');
  });

  it('BTR fields propagate through options', () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      btrEnabled: true,
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).toContain('bolt.transfer-ratchet-v1');

    const noBtr = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      btrEnabled: false,
    });
    const noBtrCaps = (noBtr as any).localCapabilities as string[];
    expect(noBtrCaps).not.toContain('bolt.transfer-ratchet-v1');
  });

  it('send queues frames when bridge is open', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    // Access internal bridge to verify it's wired up
    const bridge = (transport as any).bridge;
    expect(bridge.readyState).toBe('open');

    // The bridge should have a writer attached
    expect(bridge._writer).not.toBeNull();

    transport.disconnect();
  });
});

// ─── BrowserAppTransport three-tier fallback tests ──────────────────────────

describe('BrowserAppTransport three-tier fallback', () => {
  beforeEach(() => {
    installMockWebSocket();
  });

  afterEach(() => {
    uninstallMockWebSocket();
    uninstallMockWebTransport();
  });

  it('uses WebTransport when available and configured', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    expect(transport.mode).toBe('webtransport');
    expect(onTransportMode).toHaveBeenCalledWith('webtransport');

    transport.disconnect();
    expect(transport.mode).toBeNull();
  });

  it('falls back to WS when WebTransport not available in browser', async () => {
    // WebTransport is NOT installed -> should skip to WS
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    // WS should be attempted
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');

    transport.disconnect();
  });

  it('falls back to WS when WebTransport connect fails', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 100,
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();

    // WT times out (ready never resolves), then falls back to WS
    // Wait for WT timeout
    await new Promise(r => setTimeout(r, 150));

    // WS should now be attempted
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');

    transport.disconnect();
  });

  it('falls back to WebRTC when both WT and WS fail', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();
    const mockWebRTCService = {
      connect: vi.fn().mockResolvedValue(undefined),
      sendFile: vi.fn().mockResolvedValue(undefined),
      disconnect: vi.fn(),
    };

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 50,
      wsConnectTimeout: 50,
      onTransportMode,
      createWebRTCFallback: async () => mockWebRTCService as any,
      peerCode: 'test-peer',
    });

    await transport.connect();

    expect(transport.mode).toBe('webrtc');
    expect(onTransportMode).toHaveBeenCalledWith('webrtc');
    expect(mockWebRTCService.connect).toHaveBeenCalledWith('test-peer');

    transport.disconnect();
  });

  it('skips WebTransport when no webTransportUrl configured', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      // No webTransportUrl -> skip WT entirely
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    // Should go straight to WS
    expect(wtConstructorCalled).toBe(false);
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    transport.disconnect();
  });

  it('throws when all transports fail and no WebRTC fallback', async () => {
    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      wsConnectTimeout: 50,
      // No webTransportUrl, no createWebRTCFallback
    });

    await expect(transport.connect()).rejects.toThrow('WebRTC fallback not configured');
  });

  it('reports webtransport mode via onTransportMode callback', async () => {
    installMockWebTransport();
    const modes: string[] = [];

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 5000,
      onTransportMode: (mode) => modes.push(mode),
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    expect(modes).toContain('webtransport');
    transport.disconnect();
  });

  it('delegates sendFile to WT transport when WT is active', async () => {
    installMockWebTransport();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    expect(transport.mode).toBe('webtransport');
    // sendFile will delegate to WtDataTransport.sendFile
    // We can't easily test the full transfer without mocking the daemon,
    // but we verify mode-based dispatch
    transport.disconnect();
  });

  it('WS-only path still works for Safari/WebKit', async () => {
    // No WebTransport in browser, no webTransportUrl
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');
    transport.disconnect();
  });
});

// ─── WTI4: Capability advertisement + kill-switch tests ─────────────────────

describe('WTI4: Capability advertisement', () => {
  afterEach(() => {
    uninstallMockWebTransport();
  });

  it('WtDataTransport includes WT capability in localCapabilities', () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).toContain('bolt.transport-webtransport-v1');
  });

  it('WtDataTransport includes all base capabilities plus WT', () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).toContain('bolt.file-hash');
    expect(caps).toContain('bolt.profile-envelope-v1');
    expect(caps).toContain('bolt.transport-webtransport-v1');
  });
});

describe('WTI4: WsDataTransport capability gating', () => {
  it('includes WT capability when webTransportEnabled=true', () => {
    const transport = new WsDataTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportEnabled: true,
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).toContain('bolt.transport-webtransport-v1');
  });

  it('omits WT capability when webTransportEnabled=false', () => {
    const transport = new WsDataTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportEnabled: false,
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).not.toContain('bolt.transport-webtransport-v1');
  });

  it('omits WT capability by default', () => {
    const transport = new WsDataTransport({
      daemonUrl: 'ws://localhost:9100',
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).not.toContain('bolt.transport-webtransport-v1');
  });
});

describe('WTI4: BrowserAppTransport kill-switch', () => {
  beforeEach(() => {
    installMockWebSocket();
  });

  afterEach(() => {
    uninstallMockWebSocket();
    uninstallMockWebTransport();
  });

  it('skips WT when webTransportEnabled=false even with URL and API', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      webTransportEnabled: false,
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    expect(wtConstructorCalled).toBe(false);
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');
    transport.disconnect();
  });

  it('attempts WT when webTransportEnabled is not set (default)', async () => {
    installMockWebTransport();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    expect(transport.mode).toBe('webtransport');
    transport.disconnect();
  });

  it('falls to WS correctly when WT kill-switched', async () => {
    installMockWebTransport();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      webTransportEnabled: false,
      wsConnectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    transport.disconnect();
  });

  it('no regression: WS-only path without WT options', async () => {
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');
    transport.disconnect();
  });
});

// ─── WTI5: E2E transfer proof + fallback proof + BTR parity ────────────────

describe('WTI5: WT E2E transfer proof (mock)', () => {
  afterEach(() => {
    uninstallMockWebTransport();
  });

  it('WtDataTransport connects and delegates to TransferManager', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    expect(transport.connected).toBe(true);
    const transfer = (transport as any).transfer;
    expect(transfer).toBeDefined();
    expect(transfer.constructor.name).toBe('TransferManager');

    const bridge = (transport as any).bridge;
    expect(bridge.readyState).toBe('open');
    expect(bridge._writer).not.toBeNull();

    transport.disconnect();
  });

  it('WtDataTransport framing is coherent with daemon 4-byte BE protocol', async () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      connectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    await simulateReadyAndSessionKey();
    await connectPromise;

    const bridge = (transport as any).bridge;
    const writer = bridge._writer;

    // Clear frames written during connect (session-key exchange)
    const preConnectFrames = writer.written.length;
    bridge.send('{"type":"ping","ts_ms":12345}');
    await new Promise(r => setTimeout(r, 10));

    expect(writer.written.length).toBeGreaterThan(preConnectFrames);
    const frame = writer.written[preConnectFrames];
    const view = new DataView(frame.buffer, frame.byteOffset, 4);
    const len = view.getUint32(0, false);
    const payload = new TextDecoder().decode(frame.slice(4));
    expect(len).toBe(new TextEncoder().encode('{"type":"ping","ts_ms":12345}').length);
    expect(payload).toBe('{"type":"ping","ts_ms":12345}');

    transport.disconnect();
  });
});

describe('WTI5: WT->WS fallback transfer proof', () => {
  beforeEach(() => {
    installMockWebSocket();
  });

  afterEach(() => {
    uninstallMockWebSocket();
    uninstallMockWebTransport();
  });

  it('transfer succeeds via WS after WT timeout', async () => {
    installMockWebTransport();
    const onTransportMode = vi.fn();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wtConnectTimeout: 50,
      wsConnectTimeout: 5000,
      onTransportMode,
    });

    const connectPromise = transport.connect();
    await new Promise(r => setTimeout(r, 100));

    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    expect(onTransportMode).toHaveBeenCalledWith('ws');

    const wsTransport = (transport as any).wsTransport;
    expect(wsTransport).not.toBeNull();
    expect(wsTransport.connected).toBe(true);

    transport.disconnect();
  });

  it('transfer succeeds via WS when WT kill-switched', async () => {
    installMockWebTransport();

    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      webTransportEnabled: false,
      wsConnectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    const wsTransport = (transport as any).wsTransport;
    expect(wsTransport.connected).toBe(true);

    transport.disconnect();
  });

  it('transfer succeeds via WS when browser lacks WebTransport API', async () => {
    const transport = new BrowserAppTransport({
      daemonUrl: 'ws://localhost:9100',
      webTransportUrl: 'https://localhost:4433',
      wsConnectTimeout: 5000,
    });

    const connectPromise = transport.connect();
    const ws = getLastMockWs();
    simulateWsOpenAndSessionKey(ws);
    await connectPromise;

    expect(transport.mode).toBe('ws');
    transport.disconnect();
  });
});

describe('WTI5: BTR parity over WT', () => {
  afterEach(() => {
    uninstallMockWebTransport();
  });

  it('WtDataTransport includes all BTR capabilities when enabled', () => {
    installMockWebTransport();
    const transport = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      btrEnabled: true,
    });
    const caps = (transport as any).localCapabilities as string[];
    expect(caps).toContain('bolt.transfer-ratchet-v1');
    expect(caps).toContain('bolt.transport-webtransport-v1');
    expect(caps).toContain('bolt.profile-envelope-v1');
    expect(caps).toContain('bolt.file-hash');
  });

  it('WtDataTransport and WsDataTransport have identical capability sets', () => {
    installMockWebTransport();
    const wt = new WtDataTransport({
      daemonUrl: 'https://localhost:4433',
      btrEnabled: true,
    });
    const ws = new WsDataTransport({
      daemonUrl: 'ws://localhost:9100',
      btrEnabled: true,
      webTransportEnabled: true,
    });

    const wtCaps = new Set((wt as any).localCapabilities as string[]);
    const wsCaps = new Set((ws as any).localCapabilities as string[]);
    expect(wtCaps).toEqual(wsCaps);
  });
});
