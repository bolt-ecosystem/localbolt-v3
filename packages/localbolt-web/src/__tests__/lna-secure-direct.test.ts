/**
 * @vitest-environment-options { "url": "https://localbolt.app/" }
 *
 * Public HTTPS page → private WebTransport (Chrome Local Network Access).
 *
 * The dial must not start until the permission is granted or the browser has
 * no LNA API. Denial and an unanswered prompt stay on the secure-direct path:
 * WebRTC cannot reach a native LocalBolt peer, and ws:// stays blocked.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

let wsTransportUrls: string[] = [];
let wtTransportUrls: string[] = [];
let rtcConnectCalls: string[] = [];
let toastCalls: unknown[][] = [];
let signalHandler: ((signal: Record<string, any>) => void) | null = null;
let acceptRequestCb: (() => void) | null = null;
let phase = 'idle';
let wtConnectOk = true;
let wtConnectFailure: unknown = null;
let permissionStates: Record<string, string> = {};

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
    showToast: (...args: unknown[]) => { toastCalls.push(args); },
    createConnectionStatus: () => document.createElement('div'),
    createDeviceDiscovery: (
      _select: () => void,
      _disconnect: () => void,
      accept: () => void,
    ) => {
      acceptRequestCb = accept;
      return document.createElement('div');
    },
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
      connect() {
        this.connectFailure = wtConnectOk ? null : wtConnectFailure;
        return Promise.resolve(wtConnectOk);
      }
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

const ORIGINAL_UA = navigator.userAgent;
const PEER = 'DESKTOP-PEER';
const LAN_WT = 'https://192.168.4.25:4433';
const CERT_HASH = 'ab'.repeat(32);

const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
};

function installPermissions() {
  Object.defineProperty(navigator, 'permissions', {
    configurable: true,
    value: {
      query: async ({ name }: { name: string }) => ({
        state: permissionStates[name] ?? 'prompt',
        addEventListener() {},
        removeEventListener() {},
      }),
    },
  });
}

function removePermissions() {
  Reflect.deleteProperty(navigator, 'permissions');
}

async function mount() {
  vi.resetModules();
  const mod = await import('../components/peer-connection');
  const el = mod.createPeerConnection();
  await flush();
  return el;
}

async function acceptedWith(data: Record<string, unknown>) {
  phase = 'requesting';
  mockState.connectingTo = PEER;
  signalHandler!({ type: 'connection_accepted', from: PEER, data });
  await flush();
}

beforeEach(() => {
  wsTransportUrls = [];
  wtTransportUrls = [];
  rtcConnectCalls = [];
  toastCalls = [];
  signalHandler = null;
  acceptRequestCb = null;
  phase = 'idle';
  wtConnectOk = true;
  wtConnectFailure = null;
  permissionStates = {};
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
  removePermissions();
  (globalThis as any).WebTransport = class {};
});

afterEach(() => {
  delete (globalThis as any).WebTransport;
  removePermissions();
  Object.defineProperty(navigator, 'userAgent', { configurable: true, value: ORIGINAL_UA });
});

describe('Chrome Local Network Access on the secure-direct path', () => {
  it('is a public HTTPS origin', () => {
    expect(window.location.origin).toBe('https://localbolt.app');
  });

  it('dials immediately when this browser has no Local Network Access API', async () => {
    await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
  });

  it('dials when local-network is already granted', async () => {
    permissionStates = { 'local-network': 'granted' };
    installPermissions();
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-notice]')?.getAttribute('data-lna-status')).toBe('hidden');
  });

  it('asks in the page when local-network is prompt, and does not fall back to WebRTC', async () => {
    permissionStates = { 'local-network': 'prompt' };
    installPermissions();
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('prompt');
    expect(el.querySelector('[data-lna-title]')?.textContent).toMatch(/local network access/i);
    expect(el.querySelector('[data-lna-body]')?.textContent).toMatch(/Site settings/);
    expect(el.querySelector('[data-lna-allow]')).toBeTruthy();
    expect(mockState.connectingPhase).toBe('local-network');

    (el.querySelector('[data-lna-allow]') as HTMLButtonElement).click();
    await flush();

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
  });

  it('treats a missing local-network-access grant as not granted even when local-network is Allow', async () => {
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value: 'Mozilla/5.0 Chrome/156.0.0.0 Safari/537.36',
    });
    permissionStates = {
      'local-network': 'granted',
      'local-network-access': 'prompt',
    };
    installPermissions();
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('prompt');
  });

  it('shows a blocked notice and does not dial when local-network is denied', async () => {
    permissionStates = { 'local-network': 'denied' };
    installPermissions();
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([]);
    expect(rtcConnectCalls).toEqual([]);
    expect(wsTransportUrls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('blocked');
    expect(el.querySelector('[data-lna-body]')?.textContent).toMatch(/Site settings/);
    expect(el.querySelector('[data-lna-body]')?.textContent).toMatch(/Local network access/);
    expect(toastCalls.some((call) => String(call[0]).toLowerCase().includes('local network'))).toBe(true);
  });

  it('reports a failed dial as local-network blocked while the permission is still prompt', async () => {
    permissionStates = { 'local-network': 'prompt' };
    installPermissions();
    wtConnectOk = false;
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    (el.querySelector('[data-lna-allow]') as HTMLButtonElement).click();
    await flush();

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('blocked');
  });

  it('does not fall back to WebRTC when the dial fails after the permission was granted', async () => {
    permissionStates = { 'local-network': 'granted' };
    installPermissions();
    wtConnectOk = false;
    wtConnectFailure = new Error('connection refused');
    const el = await mount();
    await acceptedWith({ wtUrl: LAN_WT, certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('hidden');
    expect(toastCalls.some((call) => String(call[0]) === 'Connection Failed')).toBe(true);
  });

  it('dials from the Accept click when the permission is still prompt', async () => {
    permissionStates = { 'local-network': 'prompt' };
    installPermissions();
    await mount();

    phase = 'idle';
    signalHandler!({
      type: 'connection_request',
      from: PEER,
      data: { deviceName: 'MacBook Pro', deviceType: 'desktop', wtUrl: LAN_WT, certHash: CERT_HASH },
    });
    await flush();

    phase = 'incoming_request';
    acceptRequestCb!();
    await flush();

    expect(wtTransportUrls).toEqual([LAN_WT]);
    expect(rtcConnectCalls).toEqual([]);
  });

  it('asks for loopback-network, not local-network, when the daemon is on loopback', async () => {
    permissionStates = {
      'local-network': 'granted',
      'loopback-network': 'prompt',
    };
    installPermissions();
    const el = await mount();
    await acceptedWith({ wtUrl: 'https://127.0.0.1:4433', certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([]);
    expect(rtcConnectCalls).toEqual([]);
    expect(el.querySelector('[data-lna-status]')?.getAttribute('data-lna-status')).toBe('prompt');
  });

  it('still refuses ws:// from this HTTPS origin when local-network is granted', async () => {
    permissionStates = { 'local-network': 'granted' };
    installPermissions();
    await mount();
    await acceptedWith({ wsUrl: 'ws://192.168.4.25:8080' });

    expect(wsTransportUrls).toEqual([]);
    expect(wtTransportUrls).toEqual([]);
  });

  it('still refuses a public WebTransport target', async () => {
    permissionStates = { 'local-network': 'granted' };
    installPermissions();
    await mount();
    await acceptedWith({ wtUrl: 'https://attacker.example.com:4433', certHash: CERT_HASH });

    expect(wtTransportUrls).toEqual([]);
    expect(rtcConnectCalls).toEqual([PEER]);
  });
});
