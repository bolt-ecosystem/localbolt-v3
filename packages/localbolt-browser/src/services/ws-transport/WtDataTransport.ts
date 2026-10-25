/**
 * WtDataTransport -- WebTransport client for direct data transport to the
 * bolt-daemon HTTP/3 WebTransport endpoint (WTI2/WTI3).
 *
 * Uses the SAME wire format (ProfileEnvelopeV1 JSON text), EnvelopeCodec,
 * HandshakeManager, and TransferManager as the WebSocket and WebRTC paths.
 * Only the underlying transport differs: WebTransport bidirectional streams
 * with 4-byte big-endian length-prefixed framing.
 *
 * IMPORTANT: This is browser-to-daemon transport. All protocol/session
 * authority stays in the daemon/Rust core. The browser WT client just
 * sends and receives frames.
 *
 * Log tokens:
 *   [WT_TRANSPORT]  - connection lifecycle
 *   [WT_FRAMING]    - frame-level events
 */

import { generateEphemeralKeyPair, toBase64, fromBase64, openBoxPayload, isValidWireErrorCode, scalarMult, BtrMode } from '@the9ines/bolt-core';
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
import type { DataTransport } from './WsDataTransport.js';

// ─── Options ────────────────────────────────────────────────────────────────

export interface WtDataTransportOptions {
  /** Daemon WebTransport URL, e.g. "https://localhost:4433" */
  daemonUrl: string;
  /** SHA-256 cert hash (hex string) for serverCertificateHashes pinning.
   *  Required for self-signed certs (SECURE-DIRECT-1). */
  certHashHex?: string;
  /** Connection timeout in ms. Default: 5000 */
  connectTimeout?: number;
  /** Ed25519 identity keypair for HELLO handshake. */
  identity?: { publicKey: Uint8Array; secretKey: Uint8Array };
  /** Ed25519 identity public key (sent in HELLO). */
  identityPublicKey?: Uint8Array;
  /** Verification state callback. */
  onVerification?: (info: VerificationInfo) => void;
  /** Fired when a complete file is received. */
  onReceiveFile?: (file: Blob, filename: string) => void;
  /** Transfer progress callback. */
  onProgress?: (progress: TransferProgress) => void;
  /** Fired on disconnect. */
  onDisconnect?: () => void;
  /** Fired with the active transport mode. */
  onTransportMode?: (mode: 'webtransport' | 'ws' | 'webrtc') => void;
  /** Error callback. */
  onError?: (error: Error) => void;
  /** Enable BTR capability. Default: false. */
  btrEnabled?: boolean;
}

// ─── Framing Helpers ────────────────────────────────────────────────────────
// 4-byte big-endian length prefix + UTF-8 payload, matching daemon wt_endpoint.

const MAX_FRAME_SIZE = 1_048_576; // 1 MiB

/** Encode a string message into a length-prefixed frame. */
export function encodeFrame(message: string): Uint8Array {
  const payload = new TextEncoder().encode(message);
  const frame = new Uint8Array(4 + payload.length);
  const view = new DataView(frame.buffer);
  view.setUint32(0, payload.length, false); // big-endian
  frame.set(payload, 4);
  return frame;
}

/**
 * Deframer: accumulates byte chunks and yields complete frames.
 * Each frame is 4-byte BE length + payload bytes.
 */
export class FrameDeframer {
  private buffer = new Uint8Array(0);

  /** Push new bytes and return any complete frames as strings. */
  push(chunk: Uint8Array): string[] {
    // Append chunk to buffer
    const merged = new Uint8Array(this.buffer.length + chunk.length);
    merged.set(this.buffer);
    merged.set(chunk, this.buffer.length);
    this.buffer = merged;

    const frames: string[] = [];
    while (this.buffer.length >= 4) {
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, 4);
      const len = view.getUint32(0, false); // big-endian

      if (len > MAX_FRAME_SIZE) {
        throw new Error(`[WT_FRAMING] Frame too large: ${len} bytes (max ${MAX_FRAME_SIZE})`);
      }

      if (this.buffer.length < 4 + len) {
        break; // incomplete frame
      }

      const payload = this.buffer.slice(4, 4 + len);
      frames.push(new TextDecoder().decode(payload));
      this.buffer = this.buffer.slice(4 + len);
    }

    return frames;
  }

  /** Reset internal buffer. */
  reset(): void {
    this.buffer = new Uint8Array(0);
  }
}

// ─── DataTransport adapter ──────────────────────────────────────────────────
// Wraps the async WebTransport write into a sync send() + readyState shape
// that HandshakeManager and EnvelopeCodec expect.

class WtDataTransportBridge implements DataTransport {
  private _readyState: string = 'connecting';
  private _writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private _sendQueue: Uint8Array[] = [];
  private _flushing = false;

  get readyState(): string {
    return this._readyState;
  }

  setReadyState(state: string): void {
    this._readyState = state;
  }

  setWriter(writer: WritableStreamDefaultWriter<Uint8Array>): void {
    this._writer = writer;
  }

  /** Synchronous send - queues internally, flushes async. */
  send(data: string): void {
    if (this._readyState !== 'open') return;
    this._sendQueue.push(encodeFrame(data));
    this.flush();
  }

  /** Flush queued frames to the writer. */
  private async flush(): Promise<void> {
    if (this._flushing || !this._writer) return;
    this._flushing = true;
    try {
      while (this._sendQueue.length > 0) {
        const frame = this._sendQueue.shift()!;
        await this._writer.write(frame);
      }
    } catch (e) {
      console.warn('[WT_TRANSPORT] Write error during flush:', e);
    } finally {
      this._flushing = false;
    }
  }

  /** Close the writer and mark closed. */
  async close(): Promise<void> {
    this._readyState = 'closed';
    this._sendQueue = [];
    if (this._writer) {
      try { await this._writer.close(); } catch { /* ignore */ }
      this._writer = null;
    }
  }
}

// ─── WtDataTransport ────────────────────────────────────────────────────────

export class WtDataTransport {
  /** Why the latest connect() attempt failed. Null after a successful connect starts. */
  connectFailure: unknown = null;

  private transport: any | null = null; // WebTransport instance
  private bridge: WtDataTransportBridge;
  private deframer = new FrameDeframer();
  private readLoopAbort: AbortController | null = null;

  private keyPair: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private remotePublicKey: Uint8Array | null = null;
  private remoteIdentityKey: Uint8Array | null = null;

  private sessionState: 'connecting' | 'key_exchange' | 'pre_hello' | 'post_hello' | 'closed' = 'closed';
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
  private readonly opts: WtDataTransportOptions;
  private readonly wsOptions: WebRTCServiceOptions;

  constructor(options: WtDataTransportOptions) {
    this.opts = options;
    this.wsOptions = {
      identityPublicKey: options.identityPublicKey,
      onVerificationState: options.onVerification,
      btrEnabled: options.btrEnabled,
    };

    this.localCapabilities = ['bolt.file-hash', 'bolt.profile-envelope-v1', 'bolt.transport-webtransport-v1'];
    if (options.btrEnabled) {
      this.localCapabilities.push('bolt.transfer-ratchet-v1');
    }

    this.bridge = new WtDataTransportBridge();
    this.handshake = new HandshakeManager(this.buildHandshakeContext());
    this.transfer = new TransferManager(this.buildTransferContext());
  }

  // ─── Public API ─────────────────────────────────────────────────────────

  /**
   * Connect to the daemon's WebTransport endpoint.
   * Returns true on success (HELLO complete), false on failure.
   */
  async connect(): Promise<boolean> {
    const timeout = this.opts.connectTimeout ?? 5000;
    this.sessionGeneration++;
    this.sessionState = 'connecting';
    this.connectFailure = null;
    this.keyPair = generateEphemeralKeyPair();
    this.bridge = new WtDataTransportBridge();

    return new Promise<boolean>(async (resolve) => {
      const fail = (reason: unknown) => {
        // Keep the first cause. Closing the transport wakes `closed`, which
        // would otherwise replace a timeout or LNA error with "closed".
        if (this.connectFailure == null) this.connectFailure = reason;
        clearTimeout(timer);
        this.cleanupTransport();
        resolve(false);
      };

      const timer = setTimeout(() => {
        console.log('[WT_TRANSPORT] Connect timeout');
        fail(new Error('WebTransport connect timeout'));
      }, timeout);

      try {
        // Feature detection
        if (typeof globalThis.WebTransport === 'undefined') {
          clearTimeout(timer);
          console.log('[WT_TRANSPORT] WebTransport not available in this browser');
          fail(new Error('WebTransport not available'));
          return;
        }

        // Build WebTransport options - include cert hash for self-signed certs
        const wtOptions: Record<string, unknown> = {};
        if (this.opts.certHashHex) {
          const hashBytes = new Uint8Array(
            (this.opts.certHashHex.match(/.{2}/g) ?? []).map((h) => parseInt(h, 16))
          );
          wtOptions.serverCertificateHashes = [
            { algorithm: 'sha-256', value: hashBytes.buffer },
          ];
          console.log('[WT_TRANSPORT] Using serverCertificateHashes for self-signed cert');
        }

        this.transport = new globalThis.WebTransport(this.opts.daemonUrl, wtOptions);

        // Wait for transport to be ready
        await this.transport.ready;
        console.log('[WT_TRANSPORT] Connected to daemon');

        // Open one bidirectional stream
        const stream = await this.transport.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable;

        this.bridge.setWriter(writer);
        this.bridge.setReadyState('open');
        this.sessionState = 'key_exchange';

        // Start read loop
        this.readLoopAbort = new AbortController();
        this.startReadLoop(reader, this.readLoopAbort.signal);

        // Set helloResolve BEFORE initiateHello so legacy mode can resolve
        this.helloResolve = () => {
          clearTimeout(timer);
          console.log('[WT_TRANSPORT] HELLO complete');
          resolve(true);
        };

        // Send our session-key (same protocol as WS transport)
        if (this.keyPair) {
          const sessionKeyMsg = JSON.stringify({
            type: 'session-key',
            publicKey: toBase64(this.keyPair.publicKey),
          });
          this.bridge.send(sessionKeyMsg);
          console.log('[WT_TRANSPORT] Sent session-key');
        }
        // HELLO is initiated when we receive daemon's session-key (in handleMessage)

        // Listen for transport closure
        this.transport.closed.then(() => {
          console.log('[WT_TRANSPORT] Transport closed');
          if (this.sessionState !== 'post_hello') {
            clearTimeout(timer);
            fail(new Error('WebTransport closed before the session was established'));
          } else {
            this.opts.onDisconnect?.();
          }
        }).catch((e: unknown) => {
          if (this.sessionState !== 'post_hello') {
            clearTimeout(timer);
            fail(e instanceof Error ? e : new Error('WebTransport closed'));
          }
        });
      } catch (e) {
        clearTimeout(timer);
        console.log('[WT_TRANSPORT] Connection failed:', e);
        fail(e);
      }
    });
  }

  /** Send a file over the WT transport. */
  async sendFile(file: File): Promise<void> {
    return this.transfer.sendFile(file);
  }

  /** Mark the connected peer as verified. */
  async markPeerVerified(): Promise<void> {
    this.verificationInfo = { ...this.verificationInfo, state: 'verified' };
    this.opts.onVerification?.(this.verificationInfo);
    console.log('[WT_TRANSPORT] Peer marked as verified');
  }

  /** Cancel an active transfer. */
  cancelTransfer(filename: string): void {
    this.transfer.cancelTransfer(filename);
  }

  /** Pause an active transfer. */
  pauseTransfer(filename: string): void {
    this.transfer.pauseTransfer(filename);
  }

  /** Resume a paused transfer. */
  resumeTransfer(filename: string): void {
    this.transfer.resumeTransfer(filename);
  }

  /** Disconnect and clean up. */
  disconnect(): void {
    console.log('[WT_TRANSPORT] Disconnecting');
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

    this.cleanupTransport();

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
    return this.sessionState === 'post_hello' && this.bridge.readyState === 'open';
  }

  // ─── Read Loop ────────────────────────────────────────────────────────────

  private async startReadLoop(readable: ReadableStream<Uint8Array>, signal: AbortSignal): Promise<void> {
    try {
      const reader = readable.getReader();
      while (!signal.aborted) {
        const { done, value } = await reader.read();
        if (done || signal.aborted) break;

        let frames: string[];
        try {
          frames = this.deframer.push(value);
        } catch (e) {
          console.warn('[WT_FRAMING] Deframing error:', e);
          this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Frame decode error');
          break;
        }

        for (const frame of frames) {
          if (signal.aborted) break;
          this.handleMessage(frame);
        }
      }
      reader.releaseLock();
    } catch (e) {
      if (!signal.aborted) {
        console.warn('[WT_TRANSPORT] Read loop error:', e);
      }
    }
  }

  // ─── Message Handling ───────────────────────────────────────────────────

  private handleMessage(data: string): void {
    try {
      const msg = JSON.parse(data);

      // Session-key exchange (before HELLO)
      if (msg.type === 'session-key' && msg.publicKey) {
        this.remotePublicKey = fromBase64(msg.publicKey);
        console.log('[WT_TRANSPORT] Received daemon session-key');
        this.sessionState = 'pre_hello';

        // Now initiate HELLO (we have remote key)
        this.handshake.initiateHello();
        // Legacy mode resolves synchronously
        if (this.helloComplete && this.helloResolve) {
          this.helloResolve();
          this.helloResolve = null;
        }
        return;
      }

      // HELLO routing
      if (msg.type === 'hello' && msg.payload) {
        if (this.sessionState !== 'pre_hello') {
          console.warn('[WT_TRANSPORT] Duplicate HELLO - disconnecting');
          this.sendErrorAndDisconnect('DUPLICATE_HELLO', 'Duplicate HELLO');
          return;
        }
        this.handshake.processHello(msg).catch((error) => {
          console.error('[WT_TRANSPORT] HELLO error:', error);
          this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Unexpected HELLO processing error');
        });
        return;
      }

      // Pre-handshake gate
      if (this.sessionState === 'pre_hello' || this.sessionState === 'key_exchange') {
        console.warn('[WT_TRANSPORT] Non-HELLO message before handshake - disconnecting');
        this.sendErrorAndDisconnect('INVALID_STATE', 'Handshake not complete');
        return;
      }

      // Profile Envelope v1 unwrap
      if (msg.type === 'profile-envelope') {
        if (!this.negotiatedEnvelopeV1()) {
          console.warn('[WT_TRANSPORT] Envelope received but not negotiated - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_UNNEGOTIATED', 'Profile envelope not negotiated');
          return;
        }
        if (msg.version !== 1 || msg.encoding !== 'base64' || typeof msg.payload !== 'string') {
          console.warn('[WT_TRANSPORT] Invalid envelope format - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_INVALID', 'Invalid profile envelope format');
          return;
        }
        let innerBytes: Uint8Array;
        try {
          innerBytes = openBoxPayload(msg.payload, this.remotePublicKey!, this.keyPair!.secretKey);
        } catch {
          console.warn('[WT_TRANSPORT] Envelope decrypt failed - disconnecting');
          this.sendErrorAndDisconnect('ENVELOPE_DECRYPT_FAIL', 'Failed to decrypt profile envelope');
          return;
        }
        let inner: any;
        try {
          inner = JSON.parse(new TextDecoder().decode(innerBytes));
        } catch {
          console.warn('[WT_TRANSPORT] Invalid inner JSON - disconnecting');
          this.sendErrorAndDisconnect('INVALID_MESSAGE', 'Invalid inner message');
          return;
        }
        if (inner.type === 'error') {
          if (!isValidWireErrorCode(inner.code)) {
            this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Invalid inbound error code');
            return;
          }
          console.warn(`[WT_TRANSPORT] Remote error: code=${inner.code}`);
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
        console.warn('[WT_TRANSPORT] Plaintext in envelope-required session - disconnecting');
        this.sendErrorAndDisconnect('ENVELOPE_REQUIRED', 'Envelope required');
        return;
      }

      // Plaintext error handling
      if (msg.type === 'error') {
        if (!isValidWireErrorCode(msg.code)) {
          this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Invalid inbound error code');
          return;
        }
        console.warn(`[WT_TRANSPORT] Remote error: code=${msg.code}`);
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
      console.error('[WT_TRANSPORT] Protocol violation:', error);
      this.sendErrorAndDisconnect('PROTOCOL_VIOLATION', 'Protocol violation');
    }
  }

  // ─── Internal Helpers ───────────────────────────────────────────────────

  private cleanupTransport(): void {
    if (this.readLoopAbort) {
      this.readLoopAbort.abort();
      this.readLoopAbort = null;
    }
    this.bridge.close();
    this.deframer.reset();
    if (this.transport) {
      try { this.transport.close(); } catch { /* ignore */ }
      this.transport = null;
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
    if (this.bridge.readyState === 'open') {
      const errorMsg = { type: 'error', code, message };
      if (this.negotiatedEnvelopeV1() && this.helloComplete && this.keyPair && this.remotePublicKey) {
        this.bridge.send(JSON.stringify(encodeProfileEnvelopeV1(errorMsg, this.remotePublicKey, this.keyPair.secretKey)));
      } else {
        this.bridge.send(JSON.stringify(errorMsg));
      }
    }
    this.disconnect();
  }

  private wtSendMessage(innerMsg: any, btrFields?: BtrEnvelopeFields): void {
    if (this.bridge.readyState !== 'open') return;
    if (this.negotiatedEnvelopeV1() && this.helloComplete && this.keyPair && this.remotePublicKey) {
      this.bridge.send(JSON.stringify(encodeProfileEnvelopeV1(innerMsg, this.remotePublicKey, this.keyPair.secretKey, btrFields)));
    } else {
      this.bridge.send(JSON.stringify(innerMsg));
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
      getDc: () => this.bridge as any,
      getLocalPeerCode: () => 'wt-client',
      getRemotePeerCode: () => 'wt-daemon',
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
      getDc: () => this.bridge as any,
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
      sendMessage: (innerMsg, btrFields?) => this.wtSendMessage(innerMsg, btrFields),
      waitForHello: () => this.waitForHello(),
      getBtrMode: () => this.btrMode,
      getBtrAdapter: () => this.btrAdapter,
    };
  }
}
