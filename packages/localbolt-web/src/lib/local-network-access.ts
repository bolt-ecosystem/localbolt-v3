import { hostAddressSpace, isLocalEndpointUrl } from '@/lib/local-endpoint';

/**
 * Chrome Local Network Access for a public HTTPS page dialing a private
 * WebTransport URL.
 *
 * Desktop Chrome 147+ (LocalNetworkAccessChecksWebTransport) blocks that dial
 * until the origin holds the permission. The prompt is attached to the request
 * that crosses into the local address space, and Chrome will not show it for a
 * signaling callback that has no user activation — `transport.ready` just
 * fails. A failed dial must not fall through to WebRTC: a native LocalBolt
 * peer does not speak it.
 *
 * Query `local-network` / `loopback-network` only. `local-network-access` is
 * the legacy content setting (the one that was empty on the affected Chrome
 * profile while `local_network` was already Allow). Querying that legacy name
 * crashes Chrome < 137, and try/catch cannot stop the crash, so it is gated
 * on the major version.
 */

export type LnaPermissionName = 'local-network' | 'loopback-network';

export type LnaPermissionState = 'granted' | 'denied' | 'prompt' | 'unsupported';

/** First Chrome release where `local-network-access` is safe to query. */
export const LEGACY_LNA_QUERY_MIN_CHROME = 137;

const LEGACY_LNA_PERMISSION = 'local-network-access';

export const chromiumMajorVersion = (userAgent: string): number | null => {
  // CriOS is Chrome's iOS shell (WebKit). It does not host this permission.
  if (/CriOS|FxiOS|EdgiOS/.test(userAgent)) return null;
  const match = userAgent.match(/Chrom(?:e|ium)\/(\d+)/);
  if (!match) return null;
  const major = Number(match[1]);
  return Number.isFinite(major) ? major : null;
};

export const canQueryLegacyLna = (userAgent: string): boolean => {
  const major = chromiumMajorVersion(userAgent);
  return major !== null && major >= LEGACY_LNA_QUERY_MIN_CHROME;
};

/**
 * Which LNA permission a secure page needs before dialing `targetUrl`.
 *
 * Null means this dial is not an LNA crossing: insecure pages, non-public
 * pages, and targets that fail the local-host policy. Null does not admit the
 * target — callers still have to pass canUseSecureDirect / isLocalEndpointUrl.
 */
export const lnaPermissionForDirectDial = (
  targetUrl: string,
  pageUrl: string,
): LnaPermissionName | null => {
  let page: URL;
  try {
    page = new URL(pageUrl);
  } catch {
    return null;
  }

  // LNA prompts exist in secure contexts. An http page keeps the mixed-content
  // rules it already has; this gate must not start applying on LAN dev pages.
  if (page.protocol !== 'https:') return null;
  if (!isLocalEndpointUrl(targetUrl)) return null;
  if (hostAddressSpace(page.hostname) !== 'public') return null;

  let target: URL;
  try {
    target = new URL(targetUrl);
  } catch {
    return null;
  }

  const targetSpace = hostAddressSpace(target.hostname);
  if (targetSpace === 'loopback') return 'loopback-network';
  if (targetSpace === 'local') return 'local-network';
  return null;
};

/**
 * Combine the granular permission with the legacy `local-network-access`
 * setting. A legacy `prompt` wins over a granular `granted`: that is the
 * profile where `local_network` was already Allow and WebTransport still
 * failed until `local_network_access` was granted.
 */
export const combineLnaStates = (
  granular: LnaPermissionState,
  legacy: LnaPermissionState | null,
): LnaPermissionState => {
  if (granular === 'unsupported') return 'unsupported';
  if (granular === 'denied' || legacy === 'denied') return 'denied';
  if (granular === 'prompt' || legacy === 'prompt') return 'prompt';
  if (granular === 'granted') return 'granted';
  return 'unsupported';
};

export const isLocalNetworkAccessFailure = (error: unknown): boolean => {
  if (!error) return false;
  const message = error instanceof Error ? `${error.name} ${error.message}` : String(error);
  return /local[-_ ]network|ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS/i.test(message);
};

const isPermissionState = (state: string): state is 'granted' | 'denied' | 'prompt' =>
  state === 'granted' || state === 'denied' || state === 'prompt';

async function queryPermissionState(name: string): Promise<LnaPermissionState> {
  const permissions = typeof navigator === 'undefined' ? undefined : navigator.permissions;
  if (!permissions?.query) return 'unsupported';
  try {
    const status = await permissions.query({ name } as PermissionDescriptor);
    return isPermissionState(status.state) ? status.state : 'prompt';
  } catch {
    // Unrecognized permission name: this browser does not implement LNA.
    return 'unsupported';
  }
}

export async function resolveLnaState(
  name: LnaPermissionName,
  deps?: {
    query?: (permissionName: string) => Promise<LnaPermissionState>;
    userAgent?: string;
  },
): Promise<LnaPermissionState> {
  const query = deps?.query ?? queryPermissionState;
  const userAgent = deps?.userAgent ?? (typeof navigator === 'undefined' ? '' : navigator.userAgent);
  const granular = await query(name);
  if (granular === 'unsupported') return 'unsupported';
  if (!canQueryLegacyLna(userAgent)) return granular;
  const legacy = await query(LEGACY_LNA_PERMISSION);
  return combineLnaStates(granular, legacy === 'unsupported' ? null : legacy);
}

/**
 * Subscribe to permission changes. Resolves to an unsubscribe function.
 * Failures (unknown permission, no Permissions API) unsubscribe as a no-op.
 */
export async function watchLnaPermission(
  name: LnaPermissionName,
  onChange: (state: LnaPermissionState) => void,
  deps?: { userAgent?: string },
): Promise<() => void> {
  const permissions = typeof navigator === 'undefined' ? undefined : navigator.permissions;
  if (!permissions?.query) return () => {};

  const userAgent = deps?.userAgent ?? navigator.userAgent;
  const names = [name];
  if (canQueryLegacyLna(userAgent)) names.push(LEGACY_LNA_PERMISSION);

  const stops: Array<() => void> = [];
  for (const permissionName of names) {
    try {
      const status = await permissions.query({ name: permissionName } as PermissionDescriptor);
      const handler = () => {
        void resolveLnaState(name, { userAgent }).then(onChange);
      };
      status.addEventListener('change', handler);
      stops.push(() => status.removeEventListener('change', handler));
    } catch {
      // Same browsers that reject the query have nothing to watch.
    }
  }
  return () => {
    for (const stop of stops) stop();
  };
}
