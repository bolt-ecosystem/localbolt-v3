import { icons } from '@the9ines/localbolt-browser';

export function createFeatures(): HTMLElement {
  const section = document.createElement('section');
  section.setAttribute('aria-label', 'Features');
  section.className = 'space-y-6 max-w-5xl mx-auto';

  const bolt = icons.zap('inline w-2.5 h-2.5 text-gray-500');

  const features = [
    { icon: icons.shield, title: 'Encrypted Transfers', desc: 'Files are encrypted before transfer with the current Bolt Protocol stack. EA1 verified device pairing is ready for outside review, not shipped behavior yet.' },
    { icon: icons.wifi, title: 'Direct P2P Transfer', desc: 'Files transfer directly between devices over encrypted WebRTC data channels. Browser-to-browser or browser-to-desktop-app. Faster and more private than cloud uploads.' },
    { icon: icons.server, title: 'Zero Server Storage', desc: 'Your files never touch any server. Not during transfer, not after. Zero cloud storage means zero data exposure.' },
    { icon: icons.laptop, title: 'Browser &amp; Desktop App', desc: 'Use localbolt.app in any browser or download the native desktop app for macOS 14+: <a href="/download/macos/apple-silicon" class="text-neon/70 hover:text-neon transition-colors underline underline-offset-2">Apple Silicon</a> · <a href="/download/macos/intel" class="text-neon/70 hover:text-neon transition-colors underline underline-offset-2">Intel</a>. <span class="block mt-1.5 text-[10px] text-gray-600">Developer ID signed and notarized. Gatekeeper accepts a normal double-click. <a href="https://github.com/bolt-ecosystem/localbolt-native/releases/tag/localbolt-app-v2.0.3" target="_blank" rel="noopener noreferrer" class="underline hover:text-gray-400 transition-colors">Release notes &amp; checksums</a></span>' },
    { icon: icons.lock, title: 'Open Source Help Wanted', desc: "Developers can help with Rust, browser reliability, native wrappers, tests, and docs. Protocol reviewers can help examine EA1 before any verified device claims ship. Open an issue on GitHub if you can help." },
    { icon: icons.zap, title: 'Lightning Fast', desc: 'Direct peer connections transfer at local network speed. Same-network transfers never leave your LAN.' },
    { icon: icons.globe, title: 'Works on Your LAN', desc: 'Nearby devices on the same local network appear automatically. Remote-network transfer is outside LocalBolt scope.' },
    { icon: icons.clock, title: 'Real-time Transfer', desc: 'Live progress tracking, transfer speed monitoring, and pause/resume control.' },
  ];

  section.innerHTML = `
    <div class="text-center max-w-3xl mx-auto">
      <h2 class="text-2xl font-bold mb-2">Open Source Security, Ready for Review</h2>
      <p class="text-sm text-gray-500 leading-relaxed">
        LocalBolt is open source and usable today for encrypted local file transfer. The next trust milestone is outside review of the EA1 device verification proposal before it becomes wire frozen or implementation authorized.
      </p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 animate-fade-up">
      ${features.map(f => `
        <div class="group flex items-start gap-3 p-4 rounded-lg bg-white/[0.02] border border-white/5 transition-all duration-300 hover:border-neon/20 hover:bg-white/[0.04]">
          ${f.icon('w-5 h-5 text-neon/70 flex-shrink-0 mt-0.5 transition-colors duration-300 group-hover:text-neon')}
          <div class="min-w-0">
            <h3 class="text-sm font-semibold mb-1">${f.title}</h3>
            <p class="text-xs text-gray-500 leading-relaxed">${f.desc}</p>
          </div>
        </div>
      `).join('')}
    </div>
  `;
  return section;
}
