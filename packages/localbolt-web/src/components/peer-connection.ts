import { generateSecurePeerCode } from '@the9ines/bolt-core';
import {
  store, showToast,
  createConnectionStatus, createDeviceDiscovery, setWebrtcRef, setDirectTransportRef,
  createVerificationStatus,
  DualSignaling, detectDeviceType, getDeviceName, detectDevice,
  IndexedDBPinStore,
  WebRTCService, WebRTCError, SignalingError,
  BrowserAppTransport, WtDataTransport,
} from '@the9ines/bolt-transport-web';
import type { TransferProgress, SignalMessage, VerificationInfo } from '@the9ines/bolt-transport-web';
import { initIdentity } from '@/services/identity';
import { isLocalEndpointUrl, endpointScheme } from '@/lib/local-endpoint';
import {
  isLocalNetworkAccessFailure,
  lnaPermissionForDirectDial,
  resolveLnaState,
  watchLnaPermission,
} from '@/lib/local-network-access';
import type { LnaPermissionName, LnaPermissionState } from '@/lib/local-network-access';
import {
  setVerificationState, getVerificationState, isTransferAllowed,
  getPhase, getGeneration, isCurrentGeneration,
  beginRequest, receiveRequest, beginConnecting,
  markConnected, resetSession,
} from '@the9ines/localbolt-core';

let signalingRef: DualSignaling | null = null;
let rtcServiceRef: WebRTCService | null = null;
let directTransportRef: BrowserAppTransport | null = null;
let wtTransportRef: WtDataTransport | null = null;

/** wsUrl received from a desktop peer's connection_request or connection_accepted. */
let pendingDesktopWsUrl: string | null = null;
/** wtUrl + certHash received from a desktop peer (SECURE-DIRECT-1). */
let pendingDesktopWtUrl: string | null = null;
let pendingDesktopCertHash: string | null = null;

/** Whether a ws:// direct URL is reachable from the current origin.
 *  The endpoint arrives over untrusted signaling, so it must clear two
 *  independent checks: the local-host policy (LocalBolt never dials a public
 *  host directly) and this transport's own scheme rule. BrowserAppTransport
 *  speaks WebSocket only, so an https:// URL is not admissible here even when
 *  the host is local.
 *  HTTPS pages additionally cannot connect to ws:// (mixed content - browser blocks it). */
function canUseDirectWs(url: string): boolean {
  if (!isLocalEndpointUrl(url)) return false;
  const scheme = endpointScheme(url);
  if (scheme !== 'ws:' && scheme !== 'wss:') return false;
  if (window.location.protocol !== 'https:') return true;
  return url.startsWith('wss://');
}

/** Whether WebTransport with cert-hash pinning is available and applicable.
 *  A pinned cert hash proves who answers, not where they are, so the endpoint
 *  must still pass the local-host policy. WebTransport runs over HTTP/3, so
 *  only https:// is admissible - a ws:// or wss:// URL is rejected here even
 *  when the host is local and the cert hash is present. */
function canUseSecureDirect(wtUrl: string | null, certHash: string | null): boolean {
  if (!wtUrl || !certHash) return false;
  if (!isLocalEndpointUrl(wtUrl)) return false;
  if (endpointScheme(wtUrl) !== 'https:') return false;
  if (typeof globalThis.WebTransport === 'undefined') return false;
  return true;
}

/**
 * Chrome LNA gate for the secure-direct dial. This does not relax
 * canUseSecureDirect or the mixed-content rule in canUseDirectWs.
 *
 * A public HTTPS page dialing a private wtUrl needs a Local Network Access
 * grant. The browser prompt is only reliable from a user gesture, and the
 * connection_accepted handler is a signaling callback, so an ungranted
 * permission waits on an in-page button instead of failing opaquely into
 * WebRTC (a native peer cannot answer that).
 */
const WT_CONNECT_TIMEOUT_MS = 10_000;
/** Long enough for the user to answer Chrome's permission bubble. */
const WT_LNA_PROMPT_TIMEOUT_MS = 60_000;

interface SecureDirectAttempt {
  peerCode: string;
  wtUrl: string;
  certHash: string;
  gen: number;
  permission: LnaPermissionName | null;
  slowTimer?: ReturnType<typeof setTimeout> | null;
}

let pendingSecureDirect: SecureDirectAttempt | null = null;
let unwatchLna: (() => void) | null = null;
let secureDirectSettled = false;
/** Bumped when a dial is replaced or abandoned, so a late connect() result is ignored. */
let secureDirectEpoch = 0;
const lnaStateCache = new Map<LnaPermissionName, LnaPermissionState>();

interface LnaNotice {
  root: HTMLElement;
  title: HTMLElement;
  body: HTMLElement;
  allow: HTMLButtonElement;
}

let lnaNotice: LnaNotice | null = null;

function prefetchLna(wtUrl: string | null): void {
  if (!wtUrl) return;
  const permission = lnaPermissionForDirectDial(wtUrl, window.location.href);
  if (!permission || lnaStateCache.has(permission)) return;
  void resolveLnaState(permission).then((state) => {
    lnaStateCache.set(permission, state);
  });
}

function stopWatchingLna(): void {
  unwatchLna?.();
  unwatchLna = null;
}

function setLnaNotice(mode: 'hidden' | 'prompt' | 'waiting' | 'blocked'): void {
  if (!lnaNotice) return;
  const { root, title, body, allow } = lnaNotice;
  root.dataset.lnaStatus = mode;
  if (mode === 'hidden') {
    root.hidden = true;
    allow.hidden = true;
    return;
  }

  const site = window.location.host || 'this site';
  root.hidden = false;
  if (mode === 'prompt') {
    title.textContent = 'Allow local network access';
    body.textContent =
      `Chrome blocks ${site} from opening a direct connection to a device on your network until you allow it. ` +
      'Click the button, then choose Allow if Chrome asks. If no prompt appears, click the lock icon in the address bar, ' +
      'open Site settings, set Local network access to Allow, and click the button again.';
    allow.hidden = false;
    allow.disabled = false;
    allow.textContent = 'Allow local network access';
    return;
  }
  if (mode === 'waiting') {
    title.textContent = 'Waiting for Chrome to allow local network access';
    body.textContent =
      'Choose Allow on the Chrome prompt. If you do not see one, click the lock icon in the address bar, ' +
      'open Site settings, set Local network access to Allow, and try connecting again.';
    allow.hidden = true;
    return;
  }
  title.textContent = 'Local network access is blocked';
  body.textContent =
    `Chrome blocked ${site} from reaching a device on your network. ` +
    'Click the lock icon in the address bar, open Site settings, set Local network access to Allow, then try connecting again.';
  allow.hidden = true;
}

function abortWt(): void {
  const wt = wtTransportRef;
  if (!wt) return;
  // Clear the ref first so the transport's onDisconnect does not re-enter disconnect().
  wtTransportRef = null;
  wt.disconnect();
}

function presentLnaBlocked(): void {
  secureDirectEpoch++;
  stopWatchingLna();
  pendingSecureDirect = null;
  secureDirectSettled = true;
  abortWt();
  store.setState({ connectingTo: null, connectingPhase: null });
  resetSession();
  setLnaNotice('blocked');
  showToast(
    'Local network access blocked',
    'Click the lock icon, open Site settings, set Local network access to Allow, then try again.',
    'destructive',
    8000,
  );
  console.log('[LNA] Local network access is not granted; not falling back to WebRTC');
}

function failSecureDirect(): void {
  secureDirectEpoch++;
  stopWatchingLna();
  pendingSecureDirect = null;
  secureDirectSettled = true;
  abortWt();
  store.setState({ connectingTo: null, connectingPhase: null });
  setLnaNotice('hidden');
  showToast(
    'Connection Failed',
    'Unable to reach the desktop app. Check that it is open and both devices are on the same network.',
    'destructive',
    8000,
  );
  resetSession();
}

function armLnaWatch(permission: LnaPermissionName, gen: number): void {
  stopWatchingLna();
  void watchLnaPermission(permission, (state) => {
    lnaStateCache.set(permission, state);
    if (!isCurrentGeneration(gen) || secureDirectSettled) return;
    if (state === 'denied') {
      presentLnaBlocked();
      return;
    }
    // Granted from site settings while the in-page prompt is up. No browser
    // prompt is required anymore, so the dial can start without a gesture.
    if (state === 'granted' && pendingSecureDirect && !wtTransportRef) {
      const pending = pendingSecureDirect;
      setLnaNotice('waiting');
      store.setState({ connectingPhase: 'local-network' });
      startSecureDirect({ ...pending, permission, connectTimeout: WT_CONNECT_TIMEOUT_MS });
    }
  }).then((stop) => {
    if (!isCurrentGeneration(gen) || secureDirectSettled) {
      stop();
      return;
    }
    unwatchLna = stop;
  });
}

function presentLnaPrompt(attempt: SecureDirectAttempt & { permission: LnaPermissionName }): void {
  if (attempt.slowTimer) clearTimeout(attempt.slowTimer);
  pendingSecureDirect = { ...attempt, slowTimer: null };
  secureDirectSettled = false;
  store.setState({ connectingPhase: 'local-network' });
  setLnaNotice('prompt');
  armLnaWatch(attempt.permission, attempt.gen);
  showToast(
    'Allow local network access',
    'Chrome needs permission to reach this device on your network. Use the button on the page, then choose Allow.',
    'default',
    8000,
  );
  console.log('[LNA] Waiting for a user gesture before WebTransport to', attempt.wtUrl);
}

function onAllowLocalNetwork(): void {
  const pending = pendingSecureDirect;
  if (!pending || !isCurrentGeneration(pending.gen)) return;
  const cached = pending.permission ? lnaStateCache.get(pending.permission) : undefined;
  if (cached === 'denied') {
    presentLnaBlocked();
    return;
  }
  // This click is the user activation Chrome needs to show the permission prompt.
  setLnaNotice('waiting');
  store.setState({ connectingPhase: 'local-network' });
  startSecureDirect({ ...pending, connectTimeout: WT_LNA_PROMPT_TIMEOUT_MS });
}

function startSecureDirect(args: SecureDirectAttempt & { connectTimeout: number }): void {
  if (!isCurrentGeneration(args.gen)) return;
  const gen = captureGeneration();
  const epoch = ++secureDirectEpoch;
  secureDirectSettled = false;
  pendingSecureDirect = args.permission ? { ...args, gen } : null;

  if (args.permission) armLnaWatch(args.permission, gen);

  const slowTimer = args.slowTimer ?? setTimeout(() => {
    if (getPhase() === 'connecting' && store.getState().connectingPhase === 'establishing') {
      store.setState({ connectingPhase: 'slow' });
    }
  }, 10000);

  console.log('[SECURE-DIRECT] Using WtDataTransport to', args.wtUrl, 'with cert-hash pinning');
  abortWt();
  wtTransportRef = new WtDataTransport({
    daemonUrl: args.wtUrl,
    certHashHex: args.certHash,
    connectTimeout: args.connectTimeout,
    identityPublicKey: identityRef?.publicKey,
    onVerification: handleVerificationState,
    onReceiveFile: handleFileReceive,
    onProgress: handleReceiveProgress,
    onError: handleConnectionError,
    onDisconnect: () => {
      if (!wtTransportRef) return;
      console.log('[SECURE-DIRECT] WT transport disconnected by peer');
      disconnect();
    },
    btrEnabled: true,
  });

  const transport = wtTransportRef;
  const dialIsCurrent = () => epoch === secureDirectEpoch && !secureDirectSettled && isCurrentGeneration(gen);
  void transport.connect().then(async (ok) => {
    if (!dialIsCurrent()) return;
    clearTimeout(slowTimer);
    if (ok) {
      secureDirectSettled = true;
      pendingSecureDirect = null;
      stopWatchingLna();
      setLnaNotice('hidden');
      markConnected();
      setDirectTransportRef(transport as any);
      const { peers } = store.getState();
      const connDevice = peers.find((p) => p.peerCode === args.peerCode) || null;
      store.setState({
        isConnected: true,
        connectedDevice: connDevice,
        connectingTo: null,
        connectingPhase: null,
        incomingRequest: null,
        showDeviceList: false,
      });
      return;
    }

    const failure = transport.connectFailure;
    if (args.permission && isLocalNetworkAccessFailure(failure)) {
      clearTimeout(slowTimer);
      presentLnaBlocked();
      return;
    }
    if (!args.permission) {
      clearTimeout(slowTimer);
      failSecureDirect();
      return;
    }
    const state = await resolveLnaState(args.permission);
    if (!dialIsCurrent()) return;
    lnaStateCache.set(args.permission, state);
    if (state === 'denied' || state === 'prompt') {
      presentLnaBlocked();
      return;
    }
    failSecureDirect();
  }).catch(() => {
    if (!dialIsCurrent()) return;
    clearTimeout(slowTimer);
    failSecureDirect();
  });
}

function routeSecureDirect(args: {
  peerCode: string;
  wtUrl: string;
  certHash: string;
  gen: number;
  slowTimer?: ReturnType<typeof setTimeout> | null;
  userGesture: boolean;
}): void {
  const permission = lnaPermissionForDirectDial(args.wtUrl, window.location.href);
  if (!permission) {
    startSecureDirect({
      ...args,
      permission: null,
      connectTimeout: WT_CONNECT_TIMEOUT_MS,
    });
    return;
  }

  // Browsers without the Permissions API are not enforcing LNA. Decide that
  // synchronously so the dial is not deferred behind a microtask.
  if (!lnaStateCache.has(permission) && !navigator.permissions?.query) {
    lnaStateCache.set(permission, 'unsupported');
  }

  const cached = lnaStateCache.get(permission);
  if (cached === 'granted' || cached === 'unsupported') {
    startSecureDirect({ ...args, permission, connectTimeout: WT_CONNECT_TIMEOUT_MS });
    return;
  }

  // Accept is a click. Dial inside it so Chrome can show the permission
  // prompt; a cached "denied" may be stale if the user just changed settings.
  if (args.userGesture) {
    if (args.slowTimer) clearTimeout(args.slowTimer);
    setLnaNotice('waiting');
    store.setState({ connectingPhase: 'local-network' });
    startSecureDirect({ ...args, permission, connectTimeout: WT_LNA_PROMPT_TIMEOUT_MS });
    if (cached !== 'prompt') {
      void resolveLnaState(permission).then((state) => {
        lnaStateCache.set(permission, state);
        if (!isCurrentGeneration(args.gen) || secureDirectSettled) return;
        if (state === 'denied') presentLnaBlocked();
      });
    }
    return;
  }

  if (cached === 'denied') {
    if (args.slowTimer) clearTimeout(args.slowTimer);
    presentLnaBlocked();
    return;
  }
  if (cached === 'prompt') {
    presentLnaPrompt({ ...args, permission });
    return;
  }

  if (args.slowTimer) clearTimeout(args.slowTimer);
  void resolveLnaState(permission).then((state) => {
    lnaStateCache.set(permission, state);
    if (!isCurrentGeneration(args.gen)) return;
    routeSecureDirect({ ...args, slowTimer: null, userGesture: false });
  });
}

/** Generation captured when the current connection attempt began.
 *  Guards the callbacks shared by every transport (verification, progress,
 *  connection state), so it is NOT WebRTC-specific - see captureGeneration. */
let activeGeneration = 0;

/**
 * R3a: capture the session generation for the connection being established.
 *
 * resetSession() increments the generation on every disconnect, so any transport
 * that does not capture on connect stays pinned to an older value and has its
 * callbacks silently rejected from the first reconnect onward. On a direct
 * transport that would drop the TOFU identity-mismatch alert and transfer
 * progress, so every transport path must call this - WebRTC and direct alike.
 */
function captureGeneration(): number {
  activeGeneration = getGeneration();
  return activeGeneration;
}

/** Set true when current transfer reaches a terminal status (completed/canceled/error). */
let transferTerminal = false;

// RECON-XFER-1: hoisted refs for service recreation across reconnect cycles
let identityRef: { publicKey: Uint8Array } | null = null;
let localPeerCode = '';

const TERMINAL_CONNECTION_STATES: ReadonlySet<string> = new Set(['disconnected', 'failed', 'closed']);

const pinStore = new IndexedDBPinStore();

/**
 * RECON-XFER-1: Create a fresh WebRTCService for each connection attempt.
 *
 * The SDK service follows a one-shot lifecycle: the constructor registers a
 * signaling listener, disconnect() permanently removes it. A disconnected
 * service cannot receive offer/answer/ICE signals.
 *
 * Additionally, each new service captures the current localbolt-core session
 * generation so that stale callbacks from previous sessions are rejected.
 *
 * Old service handlers are fully detached before the new instance is created,
 * preventing double-callback races during the swap.
 */
function createFreshRtcService(): WebRTCService | null {
  if (!signalingRef || !identityRef) return null;

  // Fully detach old service before creating new one
  if (rtcServiceRef) {
    rtcServiceRef.setConnectionStateHandler(() => {}); // block late callbacks
    rtcServiceRef.disconnect(); // detaches signaling listener + all internal handlers
    rtcServiceRef = null;
    setWebrtcRef(null);
  }

  const rtcService = new WebRTCService(
    signalingRef,
    localPeerCode,
    handleFileReceive,
    handleConnectionError,
    handleReceiveProgress,
    {
      identityPublicKey: identityRef.publicKey,
      pinStore,
      onVerificationState: handleVerificationState,
      btrEnabled: true,
    },
  );
  rtcService.setConnectionStateHandler(handleConnectionStateChange);
  rtcServiceRef = rtcService;
  captureGeneration();
  return rtcService;
}

// Verification status UI component (SDK-provided)
let verificationStatusUpdate: ((info: VerificationInfo) => void) | null = null;

// Reject button (shown only for unverified state)
let rejectBtnRef: HTMLButtonElement | null = null;

function handleConnectionError(error: WebRTCError) {
  console.error(`[${error.name}]`, error.message, error.details);

  // Use canonical reset path
  resetSession();

  let title = 'Connection Error';
  let description = 'Failed to establish connection';
  const device = detectDevice();

  switch (error.name) {
    case 'ConnectionError':
      if (error.message.includes('key mismatch') || error.message.includes('TOFU violation')) {
        title = 'Security Alert: Identity Mismatch';
        description =
          'This device\'s identity key has changed since your last connection. ' +
          'The connection has been blocked for your safety. If this is unexpected, ' +
          'the device may have been compromised or reinstalled.';
      } else if (error.message.includes('timeout')) {
        // RU3: distinct timeout messaging
        title = 'Connection Timed Out';
        description = 'The other device may be unreachable. Check that both devices are on the same network and try again.';
      } else {
        title = 'Connection Failed';
        description = device.isLinux
          ? 'Connection failed. Please check your firewall settings.'
          : 'Unable to connect to peer. Please try again.';
      }
      break;
    case 'SignalingError':
      title = 'Signaling Error';
      description = 'Failed to establish initial connection. Please check your peer code.';
      break;
    case 'TransferError':
      title = 'Transfer Failed';
      description = device.isWindows
        ? 'File transfer failed. Please check your Windows Defender settings.'
        : 'File transfer failed. Please try again.';
      break;
    case 'EncryptionError':
      title = 'Security Error';
      description = 'Failed to encrypt/decrypt data. Please reconnect.';
      break;
  }

  showToast(title, description, 'destructive');
}

function handleConnectionStateChange(state: RTCPeerConnectionState) {
  console.log('[UI] Connection state changed:', state);

  // Guard: reject callbacks from a previous session's RTC connection
  if (!isCurrentGeneration(activeGeneration)) return;

  const connected = state === 'connected';
  const { peers } = store.getState();

  if (connected && rtcServiceRef) {
    const remotePeerCode = rtcServiceRef.getRemotePeerCode();
    const device = peers.find((p) => p.peerCode === remotePeerCode) || null;

    // Transition session to connected
    markConnected();

    store.setState({
      isConnected: true,
      connectedDevice: device,
      connectingTo: null,
      connectingPhase: null,
      incomingRequest: null,
      showDeviceList: false,
    });
    setWebrtcRef(rtcServiceRef);
  } else if (TERMINAL_CONNECTION_STATES.has(state)) {
    // Only reset on terminal states - ignore intermediates ('new', 'connecting')
    transferTerminal = false;
    // RECON-XFER-1: disconnect SDK service on terminal WebRTC state so transfer
    // maps/flags/timers are cleaned up and the one-shot service is retired
    if (rtcServiceRef) {
      rtcServiceRef.setConnectionStateHandler(() => {}); // prevent re-entrant callback
      rtcServiceRef.disconnect();
    }
    resetSession();
    setWebrtcRef(null);
    // RU5: connection drop guidance - tell user what happened and how to recover
    showToast('Connection Lost', 'The connection was interrupted. Select the device again to reconnect.', 'destructive');
  }
}

function handleVerificationState(info: VerificationInfo) {
  // Guard: reject callbacks from a previous session's RTC connection
  if (!isCurrentGeneration(activeGeneration)) return;

  console.log('[TOFU] Verification state:', info.state, info.sasCode ? `SAS: ${info.sasCode}` : '');
  setVerificationState(info);
  verificationStatusUpdate?.(info);

  // Show/hide reject button based on state
  if (rejectBtnRef) {
    rejectBtnRef.hidden = info.state !== 'unverified';
  }
}

/**
 * Inbound counterpart of the outbound gate in sections/transfer.ts. Both call
 * isTransferAllowed, so one policy governs each direction and the two cannot
 * drift apart.
 *
 * Every transport funnels here (WebRTC, direct WS, direct WebTransport) and both
 * the modern and legacy TransferManager receive paths end here, so this single
 * check covers all of them.
 *
 * This prevents WRITING the file, not receiving it: the bytes have already been
 * transferred and assembled in memory by the time this runs, and are dropped
 * rather than held. Refusing the transfer itself belongs at the protocol
 * boundary, where the SDK already rejects pre-HELLO chunks.
 */
function handleFileReceive(file: Blob, filename: string) {
  const { isConnected } = store.getState();
  const vState = getVerificationState()?.state ?? null;

  if (!isTransferAllowed(vState, isConnected)) {
    console.warn(
      '[TRANSFER] Blocked inbound file - session not allowed to transfer:',
      filename, '(verification:', vState ?? 'none', ', connected:', isConnected, ')',
    );
    showToast(
      'File Blocked',
      'An incoming file was blocked because this connection is not verified yet. Verify the connection, then ask the sender to send it again.',
      'destructive',
    );
    return;
  }

  const url = URL.createObjectURL(file);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function handleReceiveProgress(progress: TransferProgress) {
  // Guard: reject callbacks from a previous session's RTC connection
  if (!isCurrentGeneration(activeGeneration)) return;

  // Guard: ignore late progress after current transfer reached terminal status
  if (transferTerminal) return;

  store.setState({ transferProgress: progress });

  if (progress.status === 'completed') {
    transferTerminal = true;
    showToast('Transfer Complete', `${progress.filename} has been received successfully`);
    // RU4: 3s to let completion state (green checkmark) be clearly visible
    setTimeout(() => store.setState({ transferProgress: null }), 3000);
  } else if (progress.status === 'canceled_by_sender' || progress.status === 'canceled_by_receiver') {
    transferTerminal = true;
    // RU5: keep cancelled state visible briefly (transfer-progress.ts renders it)
    // then clear after 2s - matches cancel feedback timing
    showToast('Transfer Canceled', 'The file transfer was cancelled');
    setTimeout(() => store.setState({ transferProgress: null }), 2000);
  } else if (progress.status === 'error') {
    transferTerminal = true;
    store.setState({ transferProgress: null });
    // RU3: show classified error reason if available
    const reason = progress.errorDetail || 'The transfer was terminated due to an error';
    showToast('Transfer Error', reason, 'destructive');
  } else {
    // Non-terminal status (receiving, sending) - reset terminal flag for new transfer
    transferTerminal = false;
  }
}

// ── Connection Approval Protocol ─────────────────────────────────────────

function handleApprovalSignal(signal: SignalMessage) {
  // Only handle connection approval types - ignore WebRTC types
  switch (signal.type) {
    case 'connection_request': {
      console.log('[APPROVAL] Received connection request from', signal.from);
      const currentPhase = getPhase();
      if (currentPhase !== 'idle') {
        // Duplicate request from same peer (arrives via both local + cloud) - ignore
        const { incomingRequest } = store.getState();
        if (incomingRequest?.peerCode === signal.from) {
          console.log('[APPROVAL] Ignoring duplicate request from same peer:', signal.from);
          return;
        }
        // Actually busy with a different peer - auto-decline
        signalingRef?.sendSignal('connection_declined', { reason: 'busy' }, signal.from);
        return;
      }
      // Capture desktop peer's endpoint URLs
      pendingDesktopWsUrl = signal.data.wsUrl || null;
      pendingDesktopWtUrl = signal.data.wtUrl || null;
      pendingDesktopCertHash = signal.data.certHash || null;
      // Resolve LNA before the user clicks Accept so that click can dial
      // synchronously and keep its user activation.
      prefetchLna(pendingDesktopWtUrl);
      if (pendingDesktopWtUrl && pendingDesktopCertHash) {
        console.log('[APPROVAL] Desktop peer provides wtUrl:', pendingDesktopWtUrl, 'certHash:', pendingDesktopCertHash.slice(0, 16) + '...');
      }
      if (pendingDesktopWsUrl) {
        if (canUseDirectWs(pendingDesktopWsUrl)) {
          console.log('[APPROVAL] Desktop peer provides wsUrl:', pendingDesktopWsUrl);
        } else if (!canUseSecureDirect(pendingDesktopWtUrl, pendingDesktopCertHash)) {
          console.log('[APPROVAL] Desktop peer provides wsUrl:', pendingDesktopWsUrl, '(blocked - not a local endpoint, or HTTPS origin with no WT available, will use WebRTC)');
        }
      }

      // Transition session to incoming_request
      receiveRequest(signal.from);
      store.setState({
        incomingRequest: {
          peerCode: signal.from,
          deviceName: signal.data.deviceName,
          deviceType: signal.data.deviceType,
        },
        showDeviceList: false,
      });
      break;
    }

    case 'connection_accepted': {
      console.log('[APPROVAL] Connection accepted by', signal.from);
      const currentPhase = getPhase();
      const { connectingTo } = store.getState();
      if (currentPhase !== 'requesting' || connectingTo !== signal.from) return; // stale

      // Extract desktop peer endpoints from accepted signal
      const desktopWsUrl = signal.data?.wsUrl as string | undefined;
      const desktopWtUrl = signal.data?.wtUrl as string | undefined;
      const desktopCertHash = signal.data?.certHash as string | undefined;

      // Transition session to connecting
      beginConnecting(signal.from);
      setLnaNotice('hidden');
      store.setState({ connectingPhase: 'establishing' });

      const slowTimer = setTimeout(() => {
        // Leave the local-network panel in place while Chrome's prompt is up.
        if (getPhase() === 'connecting' && store.getState().connectingPhase === 'establishing') {
          store.setState({ connectingPhase: 'slow' });
        }
      }, 10000);

      // ── Transport selection: WS direct → WT secure direct → WebRTC fallback ──

      if (desktopWsUrl && canUseDirectWs(desktopWsUrl)) {
        // Path 1: Direct WS (localhost / HTTP LAN only)
        console.log('[DIRECT] Using BrowserAppTransport to', desktopWsUrl);
        const gen = captureGeneration();

        directTransportRef = new BrowserAppTransport({
          daemonUrl: desktopWsUrl,
          wsConnectTimeout: 10000,
          identityPublicKey: identityRef?.publicKey,
          onVerification: handleVerificationState,
          onReceiveFile: handleFileReceive,
          onProgress: handleReceiveProgress,
          onError: handleConnectionError,
          btrEnabled: true,
          onTransportMode: (mode) => {
            console.log('[DIRECT] Transport mode:', mode);
          },
          onDisconnect: () => {
            if (!directTransportRef) return;
            console.log('[SECURE-DIRECT] WS transport disconnected by peer');
            disconnect();
          },
        });

        directTransportRef.connect().then(() => {
          if (!isCurrentGeneration(gen)) return;
          clearTimeout(slowTimer);
          markConnected();
          setDirectTransportRef(directTransportRef);
          const { peers } = store.getState();
          const connDevice = peers.find((p) => p.peerCode === signal.from) || null;
          store.setState({
            isConnected: true,
            connectedDevice: connDevice,
            connectingTo: null,
            connectingPhase: null,
            incomingRequest: null,
            showDeviceList: false,
          });
        }).catch(() => {
          if (!isCurrentGeneration(gen)) return;
          clearTimeout(slowTimer);
          store.setState({ connectingTo: null, connectingPhase: null });
          showToast('Connection Failed', 'Unable to connect to desktop app. Check that both devices are on the same network.', 'destructive');
          resetSession();
        });

        break;
      }

      if (canUseSecureDirect(desktopWtUrl ?? null, desktopCertHash ?? null)) {
        // Path 2: Secure direct via WebTransport. LNA is handled inside
        // routeSecureDirect; a native peer does not get a WebRTC fallback.
        routeSecureDirect({
          peerCode: signal.from,
          wtUrl: desktopWtUrl!,
          certHash: desktopCertHash!,
          gen: captureGeneration(),
          slowTimer,
          userGesture: false,
        });
        break;
      }

      if (desktopWsUrl && !canUseDirectWs(desktopWsUrl)) {
        console.log('[DIRECT] ws:// blocked (non-local endpoint, or HTTPS origin with no WT available) - falling back to WebRTC');
      }

      // ── Path 3: Standard browser↔browser WebRTC fallback ──
      const service = createFreshRtcService();
      if (!service) return;

      const gen = getGeneration();
      service.connect(signal.from).catch((error) => {
        if (!isCurrentGeneration(gen)) return;
        store.setState({ connectingTo: null, connectingPhase: null });
        if (error instanceof WebRTCError) {
          handleConnectionError(error);
        } else {
          showToast('Connection Failed', 'Unable to connect to device. Please try again.', 'destructive');
        }
      });
      break;
    }

    case 'connection_declined': {
      console.log('[APPROVAL] Connection declined by', signal.from);
      const { connectingTo, incomingRequest } = store.getState();
      if (connectingTo === signal.from) {
        // We were waiting for approval - they declined
        resetSession();
        showToast('Connection Declined', 'The other device declined the connection request');
      } else if (incomingRequest?.peerCode === signal.from) {
        // They cancelled their request to us
        resetSession();
      }
      break;
    }
  }
}

function selectPeer(peerCode: string) {
  if (!signalingRef) return;

  // Use session phase guard instead of just isConnected
  if (!beginRequest(peerCode)) return;
  setLnaNotice('hidden');

  const localDeviceName = getDeviceName();
  const localDeviceType = detectDeviceType();

  // RU2: distinguish "waiting for peer" from "establishing connection"
  store.setState({ connectingTo: peerCode, connectingPhase: 'requesting', showDeviceList: false });

  // Send connection request via signaling (not WebRTC yet)
  const gen = getGeneration();
  signalingRef.sendSignal('connection_request', {
    deviceName: localDeviceName,
    deviceType: localDeviceType,
  }, peerCode).catch(() => {
    // Guard against stale callback
    if (!isCurrentGeneration(gen)) return;
    resetSession();
    showToast('Request Failed', 'Could not send connection request', 'destructive');
  });
}

function acceptRequest() {
  const { incomingRequest } = store.getState();
  if (!incomingRequest || !signalingRef) return;

  console.log('[APPROVAL] Accepting request from', incomingRequest.peerCode);

  beginConnecting(incomingRequest.peerCode);

  // Transport selection: WS direct → WT secure direct → WebRTC fallback
  const wtUrl = pendingDesktopWtUrl;
  const certHash = pendingDesktopCertHash;
  const wsUrl = pendingDesktopWsUrl;
  pendingDesktopWsUrl = null;
  pendingDesktopWtUrl = null;
  pendingDesktopCertHash = null;

  signalingRef.sendSignal('connection_accepted', {}, incomingRequest.peerCode);
  setLnaNotice('hidden');
  store.setState({ incomingRequest: null, connectingTo: incomingRequest.peerCode, connectingPhase: 'establishing' });

  if (wsUrl && canUseDirectWs(wsUrl)) {
    // Path 1: Direct WS (localhost / HTTP LAN)
    console.log('[DIRECT] Accepting desktop request, connecting to', wsUrl);
    const gen = captureGeneration();
    directTransportRef = new BrowserAppTransport({
      daemonUrl: wsUrl,
      wsConnectTimeout: 10000,
      identityPublicKey: identityRef?.publicKey,
      onVerification: handleVerificationState,
      onReceiveFile: handleFileReceive,
      onProgress: handleReceiveProgress,
      onError: handleConnectionError,
      btrEnabled: true,
    });

    directTransportRef.connect().then(() => {
      if (!isCurrentGeneration(gen)) return;
      markConnected();
      setDirectTransportRef(directTransportRef);
      const { peers } = store.getState();
      const connDevice = peers.find((p) => p.peerCode === incomingRequest.peerCode) || null;
      store.setState({
        isConnected: true,
        connectedDevice: connDevice,
        connectingTo: null,
        connectingPhase: null,
        showDeviceList: false,
      });
    }).catch(() => {
      if (!isCurrentGeneration(gen)) return;
      store.setState({ connectingTo: null, connectingPhase: null });
      showToast('Connection Failed', 'Unable to connect to desktop app.', 'destructive');
      resetSession();
    });
  } else if (canUseSecureDirect(wtUrl, certHash)) {
    // Path 2: Secure direct via WebTransport. Accept is a user gesture, so
    // routeSecureDirect may dial immediately and let Chrome show its prompt.
    routeSecureDirect({
      peerCode: incomingRequest.peerCode,
      wtUrl: wtUrl!,
      certHash: certHash!,
      gen: captureGeneration(),
      userGesture: true,
    });
  } else {
    // Path 3: Standard browser↔browser WebRTC fallback
    createFreshRtcService();
  }
}

function declineRequest() {
  const { incomingRequest } = store.getState();
  if (!incomingRequest || !signalingRef) return;

  console.log('[APPROVAL] Declining request from', incomingRequest.peerCode);
  signalingRef.sendSignal('connection_declined', { reason: 'user_declined' }, incomingRequest.peerCode);
  resetSession();
}

function cancelRequest() {
  const { connectingTo } = store.getState();
  if (!connectingTo || !signalingRef) return;

  console.log('[APPROVAL] Cancelling request to', connectingTo);
  secureDirectEpoch++;
  stopWatchingLna();
  pendingSecureDirect = null;
  secureDirectSettled = true;
  setLnaNotice('hidden');
  signalingRef.sendSignal('connection_declined', { reason: 'cancelled' }, connectingTo);
  store.setState({ connectingPhase: null });
  resetSession();
}

function disconnect() {
  // Idempotent - skip if already idle
  if (getPhase() === 'idle') return;

  secureDirectEpoch++;
  stopWatchingLna();
  pendingSecureDirect = null;
  secureDirectSettled = true;
  setLnaNotice('hidden');

  // RECON-XFER-1: detach handler before disconnect to prevent re-entrant
  // callbacks during teardown, then retire the one-shot service
  if (rtcServiceRef) {
    rtcServiceRef.setConnectionStateHandler(() => {});
    rtcServiceRef.disconnect();
    rtcServiceRef = null;
  }
  if (wtTransportRef) {
    const wt = wtTransportRef;
    // Clear refs BEFORE disconnect to prevent re-entrant onDisconnect loop
    wtTransportRef = null;
    directTransportRef = null;
    setDirectTransportRef(null);
    wt.disconnect();
  } else if (directTransportRef) {
    const dt = directTransportRef;
    // Clear refs BEFORE disconnect to prevent re-entrant onDisconnect loop
    directTransportRef = null;
    setDirectTransportRef(null);
    dt.disconnect();
  }
  pendingDesktopWsUrl = null;
  // Canonical reset - clears all state via session-state
  transferTerminal = false;
  resetSession();
  setWebrtcRef(null);
  // Show device list immediately so the UI clearly changes after disconnect
  store.setState({ showDeviceList: true });
  showToast('Disconnected', 'Select the device again to reconnect.');
}

// ── Main Component ───────────────────────────────────────────────────────

function createLnaNotice(): LnaNotice {
  const root = document.createElement('div');
  root.className = 'rounded-lg border border-neon/30 bg-neon/5 px-4 py-3 space-y-2';
  root.dataset.lnaNotice = 'true';
  root.dataset.lnaStatus = 'hidden';
  root.hidden = true;

  const title = document.createElement('p');
  title.className = 'text-sm font-medium text-white';
  title.dataset.lnaTitle = 'true';

  const body = document.createElement('p');
  body.className = 'text-xs text-gray-400';
  body.dataset.lnaBody = 'true';

  const allow = document.createElement('button');
  allow.type = 'button';
  allow.className = 'px-4 py-2 rounded-md bg-neon text-black text-sm font-medium hover:bg-neon/90 transition-colors';
  allow.dataset.lnaAllow = 'true';
  allow.hidden = true;
  allow.addEventListener('click', onAllowLocalNetwork);

  root.append(title, body, allow);
  return { root, title, body, allow };
}

export function createPeerConnection(): HTMLElement {
  const container = document.createElement('div');
  container.className = 'space-y-4';

  lnaNotice = createLnaNotice();

  container.appendChild(createConnectionStatus());

  const touchWrap = document.createElement('div');
  touchWrap.className = 'touch-manipulation';
  touchWrap.appendChild(createDeviceDiscovery(
    selectPeer,
    disconnect,
    acceptRequest,
    declineRequest,
    cancelRequest,
  ));
  container.appendChild(touchWrap);
  container.appendChild(lnaNotice.root);

  // ── Verification status UI ──────────────────────────────────────────
  const verificationRow = document.createElement('div');
  verificationRow.className = 'flex items-center gap-3';
  verificationRow.hidden = true;

  const verificationStatus = createVerificationStatus({
    onMarkVerified: () => {
      if (directTransportRef) {
        directTransportRef.markPeerVerified();
      } else if (wtTransportRef) {
        wtTransportRef.markPeerVerified();
      } else {
        rtcServiceRef?.markPeerVerified();
      }
    },
  });
  verificationStatusUpdate = verificationStatus.update;
  verificationRow.appendChild(verificationStatus.element);

  // Reject button - visible only in unverified state
  const rejectBtn = document.createElement('button');
  rejectBtn.className =
    'ml-auto px-2 py-0.5 text-xs rounded border border-red-400/30 ' +
    'text-red-400 hover:bg-red-400/10 transition-colors';
  rejectBtn.textContent = 'Reject';
  rejectBtn.hidden = true;
  rejectBtn.addEventListener('click', () => {
    console.log('[TOFU] User rejected unverified peer');
    disconnect();
    showToast('Peer Rejected', 'Connection closed - peer identity was not verified');
  });
  rejectBtnRef = rejectBtn;
  verificationRow.appendChild(rejectBtn);

  container.appendChild(verificationRow);

  // Show/hide verification row when connected
  store.subscribe(() => {
    const { isConnected } = store.getState();
    verificationRow.hidden = !isConnected;
  });

  // ── Initialize signaling + WebRTC ───────────────────────────────────
  // Persist peer code in sessionStorage so page refreshes reuse the same code.
  // This prevents phantom device entries when the old WebSocket hasn't been
  // cleaned up on the server yet (DP-3b).
  const PEER_CODE_KEY = 'bolt_peer_code';
  let peerCode = sessionStorage.getItem(PEER_CODE_KEY);
  if (!peerCode) {
    peerCode = generateSecurePeerCode();
    sessionStorage.setItem(PEER_CODE_KEY, peerCode);
  }
  localPeerCode = peerCode; // RECON-XFER-1: hoist for service recreation
  store.setState({ peerCode });
  console.log('[WEBRTC] Peer code:', peerCode);

  // Start identity load in parallel with signaling connect
  const identityPromise = initIdentity();

  // Hosted + local signaling. LocalBolt policy remains LAN/local-network scoped.
  const cloudUrl = import.meta.env.VITE_SIGNAL_URL as string | undefined;

  // Local signaling endpoint: only attempt ws:// from http:// origins.
  // HTTPS pages MUST NOT attempt ws:// (mixed content - blocked by browsers).
  // Local signaling is for dev mode and desktop-app embedded rendezvous only.
  const isSecureOrigin = window.location.protocol === 'https:';
  const localUrl = isSecureOrigin
    ? '' // Skip local signaling from HTTPS - no local rendezvous reachable
    : (import.meta.env.VITE_LOCAL_SIGNAL_URL || `ws://${window.location.hostname}:3001`);

  if (!cloudUrl) {
    console.warn('[SIGNALING] VITE_SIGNAL_URL not set - cloud signaling disabled, local-only mode');
  }
  if (isSecureOrigin && !localUrl) {
    console.log('[SIGNALING] HTTPS origin - local ws:// signaling disabled (mixed content policy)');
  }

  const signaling = new DualSignaling(localUrl, cloudUrl ?? '');
  signalingRef = signaling;

  // Update header indicator when connection state changes
  signaling.setConnectionStateHandler(() => {
    store.setState({ signalingConnected: signaling.isConnected() });
  });

  signaling.onPeerDiscovered((peer) => {
    const { peers } = store.getState();
    if (peers.some((p) => p.peerCode === peer.peerCode)) return;
    store.setState({ peers: [...peers, peer] });
  });

  signaling.onPeerLost((lostCode) => {
    const { peers } = store.getState();
    store.setState({ peers: peers.filter((p) => p.peerCode !== lostCode) });

    // Clean up if the lost peer was involved in a pending request
    const currentPhase = getPhase();
    if (currentPhase === 'requesting' || currentPhase === 'incoming_request' || currentPhase === 'connecting') {
      const { connectingTo, incomingRequest } = store.getState();
      if (connectingTo === lostCode || incomingRequest?.peerCode === lostCode) {
        resetSession();
        showToast('Device Left', 'The device you were connecting to has left');
      }
    }
  });

  // Register connection approval signal handler
  signaling.onSignal(handleApprovalSignal);

  signaling.connect(peerCode, getDeviceName(), detectDeviceType()).then(async () => {
    store.setState({ signalingConnected: true });

    const identity = await identityPromise;
    console.log('[IDENTITY] Local identity loaded');

    // RECON-XFER-1: hoist identity for service recreation across reconnect cycles
    identityRef = identity;

    // Initial service creation via factory
    createFreshRtcService();
  }).catch((err) => {
    console.error('[SIGNALING] Failed to connect:', err);
    store.setState({ signalingConnected: false });
  });

  return container;
}
