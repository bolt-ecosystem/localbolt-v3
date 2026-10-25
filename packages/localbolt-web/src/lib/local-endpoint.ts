import { isPrivateIP } from '@the9ines/bolt-transport-web';

/**
 * Host-locality check for direct-transport endpoints supplied over signaling.
 *
 * `wsUrl` / `wtUrl` arrive in relay-delivered connection_request and
 * connection_accepted payloads, so they are attacker controlled. LocalBolt is
 * LAN-scoped, so an endpoint may only be dialed when its host is local.
 *
 * Relationship to the ICE policy: the address-literal and mDNS rules are the
 * ICE rules, reused via isPrivateIP so there is one definition of "private
 * address" rather than a competing copy. Loopback is deliberately NOT the same:
 * isLocalCandidate has no loopback rule, and this helper adds one (see
 * isLoopbackHost). That difference is intentional and scoped to direct
 * transports — it is not a relaxation of the ICE policy, which is untouched.
 *
 * Scope: this answers "is the host local", nothing more. Which schemes a given
 * transport may dial is the caller's rule, because it differs per transport —
 * see endpointScheme and the gates in peer-connection.ts.
 */

/**
 * Schemes a direct endpoint may use at all: ws/wss for BrowserAppTransport,
 * https for WebTransport. This is the union across transports and is not
 * sufficient on its own — each transport narrows it further.
 */
const ALLOWED_SCHEMES: ReadonlySet<string> = new Set(['ws:', 'wss:', 'https:']);

const isIPv4Literal = (host: string): boolean => {
  const parts = host.split('.');
  return parts.length === 4
    && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
};

/**
 * Loopback: an intentional direct-transport exception, not part of the ICE
 * policy. isPrivateIP does not cover 127/8 or ::1, and isLocalCandidate has no
 * loopback rule — but a browser talking to the desktop app on the same machine
 * is the primary local-dev path, so direct transports admit it here. Loopback
 * cannot leave the host, so allowing it does not widen LocalBolt's reach.
 */
const isLoopbackHost = (host: string): boolean => {
  if (host === 'localhost' || host === 'localhost.') return true;
  if (host === '::1') return true;
  return isIPv4Literal(host) && host.startsWith('127.'); // 127.0.0.0/8
};

/** Same mDNS rule the ICE policy applies to host candidates. */
const isMdnsHost = (host: string): boolean =>
  host.endsWith('.local') || host.endsWith('.local.');

/**
 * Lowercase scheme of an endpoint URL ("ws:", "wss:", "https:"), or null if it
 * does not parse. Lets each transport enforce its own scheme rule without
 * re-parsing or string-matching the raw URL.
 */
export const endpointScheme = (rawUrl: string | null | undefined): string | null => {
  if (!rawUrl) return null;
  try {
    return new URL(rawUrl).protocol;
  } catch {
    return null;
  }
};

/**
 * Whether a relay-supplied endpoint URL points at a local host.
 *
 * Locality only — callers must also enforce the scheme their transport accepts.
 * Fails closed: anything unparseable, off-scheme, or merely plausible is
 * rejected.
 */
export const isLocalEndpointUrl = (rawUrl: string | null | undefined): boolean => {
  if (!rawUrl) return false;

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }

  if (!ALLOWED_SCHEMES.has(url.protocol)) return false;

  // URL parsing lowercases the host and strips userinfo, so credential tricks
  // like ws://192.168.1.5@attacker.example.com expose the real host here.
  const host = url.hostname;
  if (!host) return false;

  // IPv6 literals arrive bracketed: wss://[fd00::1]:443
  const isBracketed = host.startsWith('[') && host.endsWith(']');
  const bareHost = isBracketed ? host.slice(1, -1) : host;

  if (isLoopbackHost(bareHost)) return true;

  // isPrivateIP tests address prefixes, so it may only be consulted for real
  // IP literals. A DNS name such as "10.evil.com" would match its 10/8 rule.
  if (isBracketed || bareHost.includes(':')) return isPrivateIP(bareHost);
  if (isIPv4Literal(bareHost)) return isPrivateIP(bareHost);

  // A DNS name. The browser cannot safely resolve it before dialing, so admit
  // only names that are local by definition rather than trusting resolution.
  return isMdnsHost(bareHost);
};

export type HostAddressSpace = 'loopback' | 'local' | 'public';

/**
 * Address space of a hostname, using the same loopback / private / mDNS rules
 * as isLocalEndpointUrl. This does not admit anything: public names stay
 * public, and `*.localhost` is classified as loopback for the page only.
 * isLoopbackHost is unchanged, so isLocalEndpointUrl still rejects those names.
 */
export const hostAddressSpace = (hostname: string): HostAddressSpace => {
  if (!hostname) return 'public';

  const isBracketed = hostname.startsWith('[') && hostname.endsWith(']');
  const bareHost = isBracketed ? hostname.slice(1, -1) : hostname;

  if (isLoopbackHost(bareHost)) return 'loopback';
  // RFC 6761: names under .localhost resolve to loopback. The page may be
  // served from one. Direct-dial admission stays with isLocalEndpointUrl.
  if (bareHost.endsWith('.localhost') || bareHost.endsWith('.localhost.')) return 'loopback';

  if (isBracketed || bareHost.includes(':')) return isPrivateIP(bareHost) ? 'local' : 'public';
  if (isIPv4Literal(bareHost)) return isPrivateIP(bareHost) ? 'local' : 'public';
  if (isMdnsHost(bareHost)) return 'local';
  return 'public';
};
