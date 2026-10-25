/**
 * @vitest-environment-options { "url": "http://192.168.1.20:8080/" }
 *
 * An HTTP LAN page is not a Chrome LNA crossing. A prompt-state permission
 * must not delay or replace the existing secure-direct dial, and ws:// stays
 * available because this origin is not HTTPS.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

let wsTransportUrls: string[] = [];
let wtTransportUrls: string[] = [];
let rtcConnectCalls: string[] = [];
let signalHandler: ((signal: Record<string, any>) => void) | null = null;
let phase = 'idle';

const mockState: Record<string, unknown> = {};

vi.mock('@the9ines/bolt-core', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  generateSecurePeerCode: () => 'TEST-CODE',
}));

vi.mock('@the9ines/localbolt-browser', async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();

  return {
    isPrivateIP: actual.isPrivateIP,
    store: {
      getState: () => ({ ...mockState }),
      setState: (partial: Record<string, unknown>) => Object.assign(mockState, partial),
      subscribe: vi.fn(),
    },
    showToast: vi.fn(),
    createConnectionStatus: () => document.createElement('div'),
    createDeviceDiscovery: () => document.createElement('div'),
    createVerificationStatus: () => ({
      element: document.createElement('div'),
      update: vi.fn(),
    }),
    setWebrtcRef: vi.fn(),
    setDirectTransportRef: vi.fn(),
    detectDeviceType: () => 'desktop',
    getDeviceName: () => 'Test Device',
    detectDevice: () => ({ isLinux: false, isWindows: false, isMobile: false }),
    IndexedDBPinStore: class {
      getPin() { return Promise.resolve(null); }
      setPin() { return Promise.resolve(); }
      markVerified() { return Promise.resolve(); }
    },
    DualSignaling: class {
      connect() { return Promise.resolve(); }
      setConnectionStateHandler() {}
      onPeerDiscovered() {}
      onPeerLost() {}
      onSignal(fn: (signal: Record<string, any>) => void) { signalHandler = fn; }
      sendSignal() { return Promise.resolve(); }
      isConnected() { return true; }
    },
    BrowserAppTransport: class {
      constructor(opts: { daemonUrl: string }) { wsTransportUrls.push(opts.daemonUrl); }
      connect() { return Promise.resolve(); }
      disconnect() {}
      markPeerVerified() { return Promise.resolve(); }
    },
    WtDataTransport: class {
      connectFailure: unknown = null;
      constructor(opts: { daemonUrl: string }) { wtTransportUrls.push(opts.daemonUrl); }
      connect() { return Promise.resolve(true); }
      disconnect() {}
      markPeerVerified() { return Promise.resolve(); }
    },
    WebRTCService: class {
      setConnectionStateHandler() {}
      getRemotePeerCode() { return ''; }
      connect(peer: string) { rtcConnectCalls.push(peer); return Promise.resolve(); }
      disconnect() {}
      markPeerVerified() { return Promise.resolve(); }
    },
    WebRTCError: class extends Error {},
    SignalingError: class extends Error {},
  };
});

vi.mock('@the9ines/localbolt-core', () => ({
  setVerificationState: vi.fn(),
  getPhase: () => phase,
  getGeneration: () => 1,
  isCurrentGeneration: () => true,
  beginRequest: vi.fn(() => true),
  receiveRequest: vi.fn(),
  beginConnecting: vi.fn(),
  markConnected: vi.fn(),
  resetSession: vi.fn(),
}));

vi.mock('@/services/identity', () => ({
  initIdentity: vi.fn().mockResolvedValue({ publicKey: new Uint8Array(32) }),
}));

const PEER = 'DESKTOP-PEER';

beforeEach(() => {
  wsTransportUrls = [];
  wtTransportUrls = [];
  rtcConnectCalls = [];
  signalHandler = null;
  phase = 'idle';
  Object.assign(mockState, {
    signalingConnected: false,
    isConnected: false,
    peerCode: null,
    peers: [],
    connectingTo: null,
    connectingPhase: null,
    connectedDevice: null,
    incomingRequest: null,
    showDeviceList: false,
    transferProgress: null,
  });
  sessionStorage.clear?.();
  Object.defineProperty(navigator, 'permissions', {
    configurable: true,
    value: {
      query: async () => ({ state: 'prompt', addEventListener() {}, removeEventListener() {} }),
    },
  });
  (globalThis as any).WebTransport = class {};
});

afterEach(() => {
  delete (globalThis as any).WebTransport;
  Reflect.deleteProperty(navigator, 'permissions');
});

describe('HTTP LAN origin ignores Local Network Access state', () => {
  it('still dials a LAN WebTransport endpoint while the permission is prompt', async () => {
    vi.resetModules();
    const mod = await import('../components/peer-connection');
    mod.createPeerConnection();
    await Promise.resolve();

    expect(window.location.protocol).toBe('http:');
    phase = 'requesting';
    mockState.connectingTo = PEER;
    signalHandler!({
      type: 'connection_accepted',
      from: PEER,
      data: { wtUrl: 'https://192.168.4.25:4433', certHash: 'ab'.repeat(32) },
    });
    await Promise.resolve();

    expect(wtTransportUrls).toEqual(['https://192.168.4.25:4433']);
    expect(rtcConnectCalls).toEqual([]);
  });

  it('still dials ws:// to a LAN host', async () => {
    vi.resetModules();
    const mod = await import('../components/peer-connection');
    mod.createPeerConnection();
    await Promise.resolve();

    phase = 'requesting';
    mockState.connectingTo = PEER;
    signalHandler!({
      type: 'connection_accepted',
      from: PEER,
      data: { wsUrl: 'ws://192.168.4.25:8080' },
    });
    await Promise.resolve();

    expect(wsTransportUrls).toEqual(['ws://192.168.4.25:8080']);
  });
});
