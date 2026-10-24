/**
 * Local Network Access classification for the secure-direct dial.
 *
 * These tests pin the policy only. They must not widen isLocalEndpointUrl:
 * a name can be loopback for the page (*.localhost) and still be refused as a
 * relay-supplied dial target.
 */

import { describe, it, expect } from 'vitest';
import { isLocalEndpointUrl } from '@/lib/local-endpoint';
import { hostAddressSpace } from '@/lib/local-endpoint';
import {
  canQueryLegacyLna,
  chromiumMajorVersion,
  combineLnaStates,
  isLocalNetworkAccessFailure,
  lnaPermissionForDirectDial,
  resolveLnaState,
} from '@/lib/local-network-access';

describe('hostAddressSpace', () => {
  it('classifies loopback, local, and public hosts', () => {
    expect(hostAddressSpace('localhost')).toBe('loopback');
    expect(hostAddressSpace('127.0.0.1')).toBe('loopback');
    expect(hostAddressSpace('[::1]')).toBe('loopback');
    expect(hostAddressSpace('app.localhost')).toBe('loopback');

    expect(hostAddressSpace('192.168.4.25')).toBe('local');
    expect(hostAddressSpace('10.1.2.3')).toBe('local');
    expect(hostAddressSpace('desktop.local')).toBe('local');
    expect(hostAddressSpace('[fd00::1]')).toBe('local');

    expect(hostAddressSpace('localbolt.app')).toBe('public');
    expect(hostAddressSpace('93.184.216.34')).toBe('public');
  });

  it('does not admit *.localhost as a direct dial target', () => {
    expect(isLocalEndpointUrl('https://app.localhost:4433')).toBe(false);
    expect(isLocalEndpointUrl('https://127.0.0.1:4433')).toBe(true);
    expect(isLocalEndpointUrl('https://192.168.4.25:4433')).toBe(true);
    expect(isLocalEndpointUrl('https://localbolt.app:4433')).toBe(false);
  });
});

describe('lnaPermissionForDirectDial', () => {
  const page = 'https://localbolt.app/';

  it('requires local-network for a public HTTPS page dialing a LAN wtUrl', () => {
    expect(lnaPermissionForDirectDial('https://192.168.4.25:4433', page)).toBe('local-network');
  });

  it('requires loopback-network for a public HTTPS page dialing loopback', () => {
    expect(lnaPermissionForDirectDial('https://127.0.0.1:4433', page)).toBe('loopback-network');
    expect(lnaPermissionForDirectDial('https://localhost:4433', page)).toBe('loopback-network');
  });

  it('does not apply on insecure pages, local pages, or public targets', () => {
    expect(lnaPermissionForDirectDial('https://192.168.4.25:4433', 'http://192.168.1.20:8080/')).toBeNull();
    expect(lnaPermissionForDirectDial('https://192.168.4.25:4433', 'http://localhost:8080/')).toBeNull();
    expect(lnaPermissionForDirectDial('https://127.0.0.1:4433', 'https://192.168.1.20/')).toBeNull();
    expect(lnaPermissionForDirectDial('https://attacker.example.com:4433', page)).toBeNull();
  });
});

describe('legacy local-network-access query guard', () => {
  it('reads a Chromium major version and skips the crashing range', () => {
    expect(chromiumMajorVersion('Mozilla/5.0 Chrome/156.0.0.0 Safari/537.36')).toBe(156);
    expect(chromiumMajorVersion('Mozilla/5.0 Chrome/136.0.7103.59 Safari/537.36')).toBe(136);
    expect(chromiumMajorVersion('Mozilla/5.0 Chrome/156.0.0.0 Safari/537.36 Edg/156.0.0.0')).toBe(156);
    expect(chromiumMajorVersion('Mozilla/5.0 Firefox/128.0')).toBeNull();
    expect(chromiumMajorVersion('Mozilla/5.0 CriOS/156.0.0.0 Mobile')).toBeNull();

    expect(canQueryLegacyLna('Mozilla/5.0 Chrome/156.0.0.0')).toBe(true);
    expect(canQueryLegacyLna('Mozilla/5.0 Chrome/137.0.0.0')).toBe(true);
    expect(canQueryLegacyLna('Mozilla/5.0 Chrome/136.0.7103.59')).toBe(false);
    expect(canQueryLegacyLna('Mozilla/5.0 jsdom/26.1.0')).toBe(false);
  });

  it('lets a missing local-network-access grant win over local-network Allow', () => {
    expect(combineLnaStates('granted', 'prompt')).toBe('prompt');
    expect(combineLnaStates('granted', 'granted')).toBe('granted');
    expect(combineLnaStates('granted', 'denied')).toBe('denied');
    expect(combineLnaStates('prompt', 'granted')).toBe('prompt');
    expect(combineLnaStates('unsupported', 'prompt')).toBe('unsupported');
    expect(combineLnaStates('granted', null)).toBe('granted');
  });

  it('does not query local-network-access on Chrome 136', async () => {
    const queried: string[] = [];
    const state = await resolveLnaState('local-network', {
      userAgent: 'Mozilla/5.0 Chrome/136.0.7103.59',
      query: async (name) => {
        queried.push(name);
        return 'granted';
      },
    });

    expect(state).toBe('granted');
    expect(queried).toEqual(['local-network']);
  });

  it('queries local-network-access on current Chrome and surfaces a missing grant', async () => {
    const queried: string[] = [];
    const state = await resolveLnaState('local-network', {
      userAgent: 'Mozilla/5.0 Chrome/156.0.0.0',
      query: async (name) => {
        queried.push(name);
        return name === 'local-network-access' ? 'prompt' : 'granted';
      },
    });

    expect(state).toBe('prompt');
    expect(queried).toEqual(['local-network', 'local-network-access']);
  });
});

describe('isLocalNetworkAccessFailure', () => {
  it('recognizes Chrome’s local-network block', () => {
    expect(isLocalNetworkAccessFailure(new Error('net::ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS'))).toBe(true);
    expect(isLocalNetworkAccessFailure(new Error('Failed to fetch'))).toBe(false);
    expect(isLocalNetworkAccessFailure(null)).toBe(false);
  });
});
