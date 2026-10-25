import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';

const indexPath = resolve(dirname(fileURLToPath(import.meta.url)), '../../index.html');
const html = readFileSync(indexPath, 'utf8');

function contentSecurityPolicy(document: Document): string {
  return document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.getAttribute('content') ?? '';
}

function directive(csp: string, name: string): string {
  const part = csp.split(';').map((entry) => entry.trim()).find((entry) => entry.startsWith(`${name} `) || entry === name);
  return part ?? '';
}

describe('consent-gated Google Tag Manager', () => {
  const document = new JSDOM(html).window.document;
  const csp = contentSecurityPolicy(document);
  const gated = document.querySelector('script[type="text/plain"][data-cp="analytics"]');

  it('keeps the CrumbProof loader and gates the GTM-5WHC4FPB bootstrap on analytics', () => {
    expect(document.querySelector('script[src="https://crumbproof.com/v1/crumbproof.js"]')).not.toBeNull();
    expect(gated).not.toBeNull();
    expect(gated?.getAttribute('type')).toBe('text/plain');
    expect(gated?.textContent).toContain("'GTM-5WHC4FPB'");
    expect(gated?.textContent).toContain('https://www.googletagmanager.com/gtm.js?id=');
    expect(html).not.toContain('googletagmanager.com/gtag/js');
    expect(html).not.toContain('G-PNPSWKBL88');
    expect(document.querySelector('noscript')).toBeNull();
  });

  it('allows that exact inline bootstrap and the GTM/GA4 hosts it needs', () => {
    const hash = createHash('sha256').update(gated?.textContent ?? '').digest('base64');
    const scriptSrc = directive(csp, 'script-src');
    const imgSrc = directive(csp, 'img-src');

    expect(scriptSrc).toContain(`'sha256-${hash}'`);
    expect(scriptSrc).toContain('https://www.googletagmanager.com');
    expect(scriptSrc).toContain('https://crumbproof.com');
    expect(scriptSrc).toContain("'wasm-unsafe-eval'");
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(scriptSrc).not.toContain("'unsafe-eval'");

    expect(imgSrc).toContain('https://www.googletagmanager.com');
    expect(imgSrc).toContain('https://*.googletagmanager.com');
    expect(imgSrc).toContain('https://www.google-analytics.com');
    expect(imgSrc).toContain('https://*.google-analytics.com');

    expect(directive(csp, 'default-src')).toBe("default-src 'self'");
    expect(directive(csp, 'frame-ancestors')).toBe("frame-ancestors 'none'");
    expect(directive(csp, 'connect-src')).toContain('https:');
    expect(csp).not.toContain('frame-src');
  });
});
