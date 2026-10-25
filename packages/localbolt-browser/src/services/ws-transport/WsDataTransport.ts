/**
 * WsDataTransport -- WebSocket client for direct data transport to the
 * bolt-daemon WS endpoint (PM-RC-02).
 *
 * Uses the SAME wire format (ProfileEnvelopeV1 JSON text), EnvelopeCodec,
 * HandshakeManager, and TransferManager as the WebRTC path. Only the
 * underlying transport differs (WebSocket instead of RTCDataChannel).
 *
 * IMPORTANT: This is browser-to-daemon transport. All protocol/session
 * authority stays in the daemon/Rust core. The browser WS client just
 * sends and receives frames.
 */

import { generateEphemeralKeyPair, fromBase64, openBoxPayload, isValidWireErrorCode, scalarMult, BtrMode } from '@the9ines/bolt-core';
import { encodeSessionPublicKey } from './sessionKey.js';
import type { BtrModeValue } from '@the9ines/bolt-core';
import { ConnectionError, TransferError } from '../../types/webrtc-errors.js';
import type { WebRTCError } from '../../types/webrtc-errors.js';
import { HandshakeManager } from '../webrtc/HandshakeManager.js';
import { TransferManager } from '../webrtc/TransferManager.js';
import { encodeProfileEnvelopeV1, extractBtrEnvelopeFields } from '../webrtc/EnvelopeCodec.js';
import { createBtrAdapter } from '../webrtc/BtrTransferAdapter.js';
import type { WasmBtrTransferAdapter, BtrEnvelopeFields } from '../webrtc/BtrTransferAdapter.js';
import type { HandshakeContext } from '../webrtc/context.js';
import type { TransferContext } from '../webrtc/TransferManager.js';
import { CANONICAL_CONTROL_TYPES } from '../webrtc/types.js';
import type {
  TransferProgress,
  VerificationInfo,
  VerificationState,
  WebRTCServiceOptions,
  ActiveTransfer,
} from '../webrtc/types.js';
import type { TransferMetricsCollector } from '../webrtc/transferMetrics.js';

// ─── DataTransport abstraction ─────────────────────────────────────────────
// Minimal interface satisfied by both WebSocket and RTCDataChannel.
// Used to abstract the send target in dcSendMessage.

export interface DataTransport {
  send(data: string): void;
  readonly readyState: string;
}

// ─── Options ────────────────────────────────────────────────────────────────

export interface WsDataTransportOptions {
  /** Daemon WebSocket URL, e.g. "ws://localhost:9100" */
  daemonUrl: string;
  /** Connection timeout in ms. Default: 5000 */
  connectTimeout?: number;
  /** Ed25519 identity keypair for HELLO handshake. */
  identity?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** Ed25519 identity public key (sent in HELLO). */
  identityPublicKey?: Uint8Array;
  /** Verification state callback. */
  onVerification?: (info: VerificationInfo) => void;
  /** Fired when a complete file is received. Matches WebRTCService convention. */
  onReceiveFile?: (file: Blob, filename: string) => void;
  /** Transfer progress callback. */
  onProgress?: (progress: TransferProgress) => void;
  /** Fired on disconnect. */
  onDisconnect?: () => void;
  /** Fired with the active transport mode. */
  onTransportMode?: (mode: 'ws' | 'webrtc') => void;
  /** Error callback. */
  onError?: (error: Error) => void;
  /** Enable BTR capability. Default: false. */
  btrEnabled?: boolean;
  /** Advertise WebTransport capability in HELLO (WTI4). Default: false.
   *  Set to true when the browser is configured to use WebTransport,
   *  so the daemon knows this client supports WT even on a WS connection. */
  webTransportEnabled?: boolean;
}

// ─── WsDataTransport ────────────────────────────────────────────────────────

export class WsDataTransport {
  private ws: WebSocket | null = null;
  private keyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private remotePublicKey: Uint8Array | null = null;
  private remoteIdentityKey: Uint8Array | null = null;

  private sessionState: 'connecting' | 'pre_hello' | 'post_hello' | 'closed' = 'closed';
  private helloComplete = false;
  private sessionLegacy = false;
  private helloTimeout: ReturnType<typeof setTimeout> | null = null;
  private helloResolve: (() => void) | null = null;
  private helloProcessing = false;
  private sessionGeneration = 0;

  private verificationInfo: VerificationInfo = { state: 'legacy', sasCode: null };

  // Capabilities
  private localCapabilities: string[];
  private remoteCapabilities: string[] = [];
  private negotiatedCapabilities: string[] = [];

  // Transfer state
  private transferPaused = false;
  private transferCancelled = false;
  private receiveBuffers: Map<string, (Blob | null)[]> = new Map();
  private guardedTransfers: Map<string, ActiveTransfer> = new Map();
  private sendTransferIds: Map<string, string> = new Map();
  private recvTransferIds: Map<string, string> = new Map();
  private transferStartTime = 0;
  private pauseDuration = 0;
  private lastPausedAt: number | null = null;
  private metricsCollector: TransferMetricsCollector | null = null;
  private metricsFirstProgressRecorded = false;
  private backpressureReject?: (err: Error) => void;
  private completionTimeout: ReturnType<typeof setTimeout> | null = null;

  // BTR
  private btrMode: BtrModeValue | null = null;
  private btrAdapter: WasmBtrTransferAdapter | null = null;

  // Managers
  private handshake: HandshakeManager;
  private transfer: TransferManager;

  // Options
  private readonly opts: WsDataTransportOptions;
  private readonly wsOptions: WebRTCServiceOptions;

  constructor(options: WsDataTransportOptions) {
    this.opts = options;
    this.wsOptions = {
      identityPublicKey: options.identityPublicKey,
      onVerificationState: options.onVerification,
      btrEnabled: options.btrEnabled,
    };

    this.localCapabilities = ['bolt.file-hash', 'bolt.profile-envelope-v1'];
    if (options.btrEnabled) {
      this.localCapabilities.push('bolt.transfer-ratchet-v1');
    }
    if (options.webTransportEnabled) {
      this.localCapabilities.push('bolt.transport-webtransport-v1');
    }

    this.handshake = new HandshakeManager(this.buildHandshakeContext());
    this.transfer = new TransferManager(this.buildTransferContext());
  }

  // ─── Public API ─────────────────────────────────────────────────────────

  /**
   * Connect to the daemon's WS endpoint.
   * Returns true on success (HELLO complete), false on failure.
   */
  async connect(): Promise<boolean> {
    const timeout = this.opts.connectTimeout ?? 5000;
    this.sessionGeneration++;
    this.sessionState = 'connecting';
    this.keyPair = generateEphemeralKeyPair();

    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        console.log('[WS_TRANSPORT] Connect timeout');
        this.cleanupWs();
        resolve(false);
      }, timeout);

      try {
        this.ws = new WebSocket(this.opts.daemonUrl);
      } catch (e) {
        clearTimeout(timer);
        console.log('[WS_TRANSPORT] WebSocket constructor threw:', e);
        resolve(false);
        return;
      }

      this.ws.onopen = () => {
        console.log('[WS_TRANSPORT] Connected to daemon');
        this.sessionState = 'pre_hello';

        // WS protocol: send our session-key first, then wait for daemon's
        // session-key response (handled in handleMessage). Once we have
        // the daemon's session key, initiateHello() is called from there.
        if (this.keyPair && this.ws) {
          try {
            const sessionKeyMsg = JSON.stringify({
              type: 'session-key',
              publicKey: encodeSessionPublicKey(this.keyPair.publicKey),
            });
            this.ws.send(sessionKeyMsg);
            console.log('[WS_TRANSPORT] Sent session-key');
          } catch (e) {
            console.error('[WS_TRANSPORT] Failed to send session-key:', e);
          }
        } else {
          console.error('[WS_TRANSPORT] onopen but keyPair or ws missing!', { hasKeyPair: !!this.keyPair, hasWs: !!this.ws });
        }
      };

      this.ws.onmessage = (event: MessageEvent) => {
        this.handleMessage(event);
      };

      this.ws.onerror = () => {
        console.log('[WS_TRANSPORT] Connection error');
        clearTimeout(timer);
        this.cleanupWs();
        resolve(false);
      };

      this.ws.onclose = () => {
        console.log('[WS_TRANSPORT] Connection closed');
        if (this.sessionState !== 'post_hello') {
          clearTimeout(timer);
          this.cleanupWs();
          resolve(false);
        } else {
          this.opts.onDisconnect?.();
        }
      };

      // Resolve when HELLO completes
      this.helloResolve = () => {
        clearTimeout(timer);
        console.log('[WS_TRANSPORT] HELLO complete');
        resolve(true);
      };
    });
  }

  /** Send a file over the WS transport. */
  async sendFile(file: File): Promise<void> {
    return this.transfer.sendFile(file);
  }

  /** Mark the connected peer as verified (TOFU). */
  async markPeerVerified(): Promise<void> {
    this.verificationInfo = { ...this.verificationInfo, state: 'verified' };
    this.opts.onVerification?.(this.verificationInfo);
    console.log('[WS_TRANSPORT] Peer marked as verified');
  }

  /** Disconnect and clean up. */
  disconnect(): void {
    console.log('[WS_TRANSPORT] Disconnecting');
    this.sessionGeneration++;

    if (this.keyPair) {
      this.keyPair.secretKey.fill(0);
      this.keyPair = null;
    }

    if (this.backpressureReject) {
      this.backpressureReject(new TransferError('Transfer aborted: disconnected'));
      this.backpressureReject = undefined;
    }

    if (this.completionTimeout) {
      clearTimeout(this.completionTimeout);
      this.completionTimeout = null;
    }

    this.cleanupWs();

    if (this.remotePublicKey instanceof Uint8Array) this.remotePublicKey.fill(0);
    this.remotePublicKey = null;
    if (this.remoteIdentityKey instanceof Uint8Array) this.remoteIdentityKey.fill(0);
    this.remoteIdentityKey = null;

    this.transferPaused = false;
    this.transferCancelled = false;
    this.receiveBuffers.clear();
    this.guardedTransfers.clear();
    this.sendTransferIds.clear();
    this.recvTransferIds.clear();

    this.sessionState = 'closed';
    if (this.helloTimeout) {
      clearTimeout(this.helloTimeout);
      this.helloTimeout = null;
    }
    this.helloComplete = false;
    this.helloProcessing = false;
    this.sessionLegacy = false;
    this.helloResolve = null;
    this.verificationInfo = { state: 'legacy', sasCode: null };
    this.remoteCapabilities = [];
    this.negotiatedCapabilities = [];

    if (this.btrAdapter) {
      this.btrAdapter.cleanupDisconnect();
      this.btrAdapter = null;
    }
    this.btrMode = null;

    this.opts.onDisconnect?.();
  }

  /** Whether the transport is connected and HELLO-complete. */
  get connected(): boolean {
    return this.sessionState === 'post_hello' && this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  // ─── Message Handling ───────────────────────────────────────────────────

  private handleMessage(event: MessageEvent): void {
    try {
      const msg = JSON.parse(event.data);

      // Session-key exchange (WS transport protocol - before HELLO)
      if (msg.type === 'session-key' && msg.publicKey) {
        const remoteSessionPk = fromBase64(msg.publicKey);
        this.remotePublicKey = remoteSessionPk;
        console.log('[WS_TRANSPORT] Received daemon session-key');

        // Now that we have the remote key, initiate HELLO if we have identity
        if (!this.helloComplete) {
          this.handshake.initiateHello();
          // If legacy mode (no identity), HandshakeManager set helloComplete=true
          // but never sent a HELLO frame. The daemon WS protocol requires a HELLO
          // frame to proceed, so send a plaintext legacy HELLO.
          if (this.helloComplete && this.sessionLegacy && this.ws) {
            const legacyHello = JSON.stringify({
              type: 'hello',
              version: 1,
              legacy: true,
              capabilities: this.localCapabilities,
            });
            this.ws.send(legacyHello);
            console.log('[WS_TRANSPORT] Sent legacy HELLO (no identity)');
          }
          if (this.helloComplete && this.helloResolve) {
            this.helloResolve();
            this.helloResolve = null;
          }
        }
        return;
      }

      // Legacy HELLO response from daemon (no payload, just ack)
      if (msg.type === 'hello' && msg.legacy) {
        console.log('[WS_TRANSPORT] Received daemon legacy HELLO response');
        return;
      }

      // HELLO routing
      if (msg.type === 'hello' && msg.payload) {
        if (this.sessionState !== 'pre_hello') {
          console.warn('[WS_TRANSPORT] Duplicate HELLO - disconnecting');
          this.sendErrorAndDisconnect('DUPLICATE_HELLO', 'Duplicate HELLO');
          return;
        }
        this.handshake.processHello(msg).catch((error) => {
          console.error('[WS_TRANSPORT] HELLO error:', error);
          this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Unexpected HELLO processing error');
        });
        return;
      }

      // Pre-handshake gate
      if (this.sessionState === 'pre_hello') {
        console.warn('[WS_TRANSPORT] Non-HELLO message before handshake - disconnecting');
        this.sendErrorAndDisconnect('INVALID_STATE', 'Handshake not complete');
        return;
      }

      // Profile Envelope v1 unwrap
      if (msg.type === 'profile-envelope') {
        if (!this.negotiatedEnvelopeV1()) {
          console.warn('[WS_TRANSPORT] Envelope received but not negotiated - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_UNNEGOTIATED', 'Profile envelope not negotiated');
          return;
        }
        if (msg.version !== 1 || msg.encoding !== 'base64' || typeof msg.payload !== 'string') {
          console.warn('[WS_TRANSPORT] Invalid envelope format - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_INVALID', 'Invalid profile envelope format');
          return;
        }
        let innerBytes: Uint8Array;
        try {
          innerBytes = openBoxPayload(msg.payload, this.remotePublicKey!, this.keyPair!.secretKey);
        } catch {
          console.warn('[WS_TRANSPORT] Envelope decrypt failed - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_DECRYPT_FAIL', 'Failed to decrypt profile envelope');
          return;
        }
        let inner: any;
        try {
          inner = JSON.parse(new TextDecoder().decode(innerBytes));
        } catch {
          console.warn('[WS_TRANSPORT] Invalid inner JSON - disconnecting');
          this.sendErrorAndDisconnect('INVALID_MESSAGE', 'Invalid inner message');
          return;
        }
        if (inner.type === 'error') {
          if (!isValidWireErrorCode(inner.code)) {
            this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Invalid inbound error code');
            return;
          }
          console.warn(`[WS_TRANSPORT] Remote error: code=${inner.code}`);
          this.opts.onError?.(new Error(inner.message || 'Remote error'));
          this.disconnect();
          return;
        }
        if (CANONICAL_CONTROL_TYPES.has(inner.type)) {
          if (!inner.transferId) {
            this.sendErrorAndDisconnect('INVALID_MESSAGE', `${inner.type} missing transferId`);
            return;
          }
          this.transfer.routeInnerMessage(inner);
          return;
        }
        if (inner.type !== 'file-chunk') {
          this.sendErrorAndDisconnect('UNKNOWN_MESSAGE_TYPE', `Unknown message type: ${inner.type}`);
          return;
        }
        if (!inner.filename) {
          this.sendErrorAndDisconnect('INVALID_MESSAGE', 'file-chunk missing filename');
          return;
        }
        const btrFields = extractBtrEnvelopeFields(msg);
        if (btrFields) {
          inner._btrEnvelopeFields = btrFields;
        }
        this.transfer.routeInnerMessage(inner);
        return;
      }

      // Envelope-required enforcement
      if (this.negotiatedEnvelopeV1()) {
        console.warn('[WS_TRANSPORT] Plaintext in envelope-required session - disconnecting');
        this.sendErrorAndDisconnect('ENVELOPE_REQUIRED', 'Envelope required');
        return;
      }

      // Plaintext error handling
      if (msg.type === 'error') {
        if (!isValidWireErrorCode(msg.code)) {
          this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Invalid inbound error code');
          return;
        }
        console.warn(`[WS_TRANSPORT] Remote error: code=${msg.code}`);
        this.opts.onError?.(new Error(msg.message || 'Remote error'));
        this.disconnect();
        return;
      }

      if (CANONICAL_CONTROL_TYPES.has(msg.type)) {
        if (!msg.transferId) {
          this.sendErrorAndDisconnect('INVALID_MESSAGE', `${msg.type} missing transferId`);
          return;
        }
        this.transfer.routeInnerMessage(msg);
        return;
      }
      if (msg.type !== 'file-chunk') {
        this.sendErrorAndDisconnect('UNKNOWN_MESSAGE_TYPE', `Unknown message type: ${msg.type}`);
        return;
      }
      if (!msg.filename) {
        this.sendErrorAndDisconnect('INVALID_MESSAGE', 'file-chunk missing filename');
        return;
      }
      this.transfer.routeInnerMessage(msg);
    } catch (error) {
      console.error('[WS_TRANSPORT] Protocol violation:', error);
      this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Protocol violation');
    }
  }

  // ─── Internal Helpers ───────────────────────────────────────────────────

  private cleanupWs(): void {
    if (this.ws) {
      this.ws.onopen = null;
      this.ws.onmessage = null;
      this.ws.onerror = null;
      this.ws.onclose = null;
      try { this.ws.close(); } catch { /* ignore */ }
      this.ws = null;
    }
    this.sessionState = 'closed';
  }

  private negotiatedEnvelopeV1(): boolean {
    return this.negotiatedCapabilities.includes('bolt.profile-envelope-v1');
  }

  private sendErrorAndDisconnect(code: string, message: string): void {
    if (!isValidWireErrorCode(code)) {
      console.error(`[BUG] sendErrorAndDisconnect called with non-canonical code: ${code}`);
      this.disconnect();
      return;
    }
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      const errorMsg = { type: 'error', code, message };
      if (this.negotiatedEnvelopeV1() && this.helloComplete && this.keyPair && this.remotePublicKey) {
        this.ws.send(JSON.stringify(encodeProfileEnvelopeV1(errorMsg, this.remotePublicKey, this.keyPair.secretKey)));
      } else {
        this.ws.send(JSON.stringify(errorMsg));
      }
    }
    this.disconnect();
  }

  private wsSendMessage(innerMsg: any, btrFields?: BtrEnvelopeFields): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    if (this.negotiatedEnvelopeV1() && this.helloComplete && this.keyPair && this.remotePublicKey) {
      this.ws.send(JSON.stringify(encodeProfileEnvelopeV1(innerMsg, this.remotePublicKey, this.keyPair.secretKey, btrFields)));
    } else {
      this.ws.send(JSON.stringify(innerMsg));
    }
  }

  waitForHello(): Promise<void> {
    if (this.helloComplete) return Promise.resolve();
    return new Promise<void>((resolve) => {
      this.helloResolve = resolve;
    });
  }

  // ─── Context Bridges ────────────────────────────────────────────────────

  private buildHandshakeContext(): HandshakeContext {
    return {
      getKeyPair: () => this.keyPair,
      getRemotePublicKey: () => this.remotePublicKey,
      getDc: () => this.ws as any,  // WS satisfies the send/readyState interface
      getLocalPeerCode: () => 'ws-client',
      getRemotePeerCode: () => 'ws-daemon',
      getOptions: () => this.wsOptions,
      onFatalError: (code, message) => this.sendErrorAndDisconnect(code, message),
      onError: (error) => this.opts.onError?.(error),
      disconnect: () => this.disconnect(),
      isHelloComplete: () => this.helloComplete,
      setHelloComplete: (v) => { this.helloComplete = v; },
      getSessionState: () => this.sessionState === 'connecting' ? 'pre_hello' : this.sessionState as any,
      setSessionState: (v) => {
        if (v === 'post_hello') this.sessionState = 'post_hello';
        else if (v === 'closed') this.sessionState = 'closed';
        else this.sessionState = 'pre_hello';
      },
      getSessionGeneration: () => this.sessionGeneration,
      isHelloProcessing: () => this.helloProcessing,
      setHelloProcessing: (v) => { this.helloProcessing = v; },
      getHelloTimeout: () => this.helloTimeout,
      setHelloTimeout: (v) => { this.helloTimeout = v; },
      getHelloResolve: () => this.helloResolve,
      setHelloResolve: (v) => { this.helloResolve = v; },
      setSessionLegacy: (v) => { this.sessionLegacy = v; },
      getVerificationInfo: () => this.verificationInfo,
      setVerificationInfo: (v) => { this.verificationInfo = v; },
      getRemoteIdentityKey: () => this.remoteIdentityKey,
      setRemoteIdentityKey: (v) => { this.remoteIdentityKey = v; },
      getLocalCapabilities: () => this.localCapabilities,
      getNegotiatedCapabilities: () => this.negotiatedCapabilities,
      setNegotiatedCapabilities: (v) => { this.negotiatedCapabilities = v; },
      setRemoteCapabilities: (v) => { this.remoteCapabilities = v; },
      getBtrMode: () => this.btrMode,
      setBtrMode: (v) => {
        this.btrMode = v as BtrModeValue | null;
        if (v === BtrMode.FullBtr && this.keyPair && this.remotePublicKey) {
          const sharedSecret = scalarMult(this.keyPair.secretKey, this.remotePublicKey);
          this.btrAdapter = createBtrAdapter(sharedSecret);
        }
      },
    };
  }

  private buildTransferContext(): TransferContext {
    return {
      getKeyPair: () => this.keyPair,
      getRemotePublicKey: () => this.remotePublicKey,
      getDc: () => this.ws as any,  // WS satisfies send/readyState for TransferManager
      isHelloComplete: () => this.helloComplete,
      getSessionGeneration: () => this.sessionGeneration,
      hasCapability: (name) => this.negotiatedCapabilities.includes(name),
      negotiatedEnvelopeV1: () => this.negotiatedCapabilities.includes('bolt.profile-envelope-v1'),
      getTransferPaused: () => this.transferPaused,
      setTransferPaused: (v) => { this.transferPaused = v; },
      getTransferCancelled: () => this.transferCancelled,
      setTransferCancelled: (v) => { this.transferCancelled = v; },
      getReceiveBuffers: () => this.receiveBuffers,
      getGuardedTransfers: () => this.guardedTransfers,
      getSendTransferIds: () => this.sendTransferIds,
      getRecvTransferIds: () => this.recvTransferIds,
      getTransferStartTime: () => this.transferStartTime,
      setTransferStartTime: (v) => { this.transferStartTime = v; },
      getPauseDuration: () => this.pauseDuration,
      setPauseDuration: (v) => { this.pauseDuration = v; },
      getLastPausedAt: () => this.lastPausedAt,
      setLastPausedAt: (v) => { this.lastPausedAt = v; },
      getMetricsCollector: () => this.metricsCollector,
      setMetricsCollector: (v) => { this.metricsCollector = v; },
      getMetricsFirstProgressRecorded: () => this.metricsFirstProgressRecorded,
      setMetricsFirstProgressRecorded: (v) => { this.metricsFirstProgressRecorded = v; },
      getBackpressureReject: () => this.backpressureReject,
      setBackpressureReject: (v) => { this.backpressureReject = v; },
      getCompletionTimeout: () => this.completionTimeout,
      setCompletionTimeout: (v) => { this.completionTimeout = v; },
      getOnProgressCallback: () => this.opts.onProgress,
      getRemoteIdentityKey: () => this.remoteIdentityKey,
      onReceiveFile: (file, filename) => this.opts.onReceiveFile?.(file, filename),
      onError: (error) => this.opts.onError?.(error),
      disconnect: () => this.disconnect(),
      sendMessage: (innerMsg, btrFields?) => this.wsSendMessage(innerMsg, btrFields),
      waitForHello: () => this.waitForHello(),
      getBtrMode: () => this.btrMode,
      getBtrAdapter: () => this.btrAdapter,
    };
  }
}
