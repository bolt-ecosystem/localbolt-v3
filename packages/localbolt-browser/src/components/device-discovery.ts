import { icons } from '../ui/icons.js';
import { store } from '../state/store.js';
import { escapeHTML } from '../lib/sanitize.js';
import type { DiscoveredDevice } from '../services/signaling/SignalingProvider.js';

const deviceIconMap: Record<string, (cls: string) => string> = {
  phone: icons.smartphone,
  tablet: icons.tablet,
  laptop: icons.laptop,
  desktop: icons.monitor,
};

// ── State A: Default - "Devices" button ──────────────────────────────────

function renderDevicesButton(peerCount: number, onClick: () => void): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'flex justify-center';

  const btn = document.createElement('button');
  btn.className = `
    relative inline-flex items-center gap-2.5 px-5 py-2.5 rounded-lg
    border border-white/10 bg-dark-accent/60 hover:border-neon/20 hover:bg-dark-accent
    transition-all duration-200 active:scale-[0.98] text-sm text-gray-300 hover:text-white
  `;
  btn.innerHTML = `
    ${icons.smartphone('w-4 h-4 text-gray-500')}
    <span>Devices</span>
    ${peerCount > 0 ? `<span class="flex items-center justify-center w-5 h-5 rounded-full bg-neon/15 text-neon text-xs font-bold">${peerCount}</span>` : ''}
  `;
  btn.addEventListener('click', onClick);
  wrap.appendChild(btn);
  return wrap;
}

// ── State B: Device list popup ───────────────────────────────────────────

function renderDeviceList(
  peers: DiscoveredDevice[],
  onSelect: (code: string) => void,
  onClose: () => void,
): HTMLElement {
  const overlay = document.createElement('div');
  overlay.className = 'space-y-3 animate-fade-in';

  // Header
  const header = document.createElement('div');
  header.className = 'flex items-center justify-between';
  header.innerHTML = `
    <span class="text-sm font-medium text-white/80">Select a device</span>
  `;
  const closeBtn = document.createElement('button');
  closeBtn.className = 'text-gray-500 hover:text-white transition-colors p-1';
  closeBtn.innerHTML = icons.x('w-4 h-4');
  closeBtn.addEventListener('click', onClose);
  header.appendChild(closeBtn);
  overlay.appendChild(header);

  if (peers.length === 0) {
    const searching = document.createElement('div');
    searching.className = 'flex items-center gap-2.5 py-4 px-3.5 rounded-md bg-dark-accent/60 border border-white/5';
    searching.innerHTML = `
      <div class="relative flex items-center justify-center w-4 h-4">
        <div class="absolute w-3 h-3 rounded-full bg-neon/10 animate-ping"></div>
        <div class="w-1.5 h-1.5 rounded-full bg-neon/40"></div>
      </div>
      <span class="text-xs text-gray-400">Searching for nearby devices...</span>
    `;
    overlay.appendChild(searching);
  } else {
    const list = document.createElement('div');
    list.className = 'space-y-1.5';

    peers.forEach((peer) => {
      const iconFn = deviceIconMap[peer.deviceType] || icons.laptop;
      const btn = document.createElement('button');
      btn.className = `
        group flex items-center gap-3 w-full px-3.5 py-3 rounded-lg
        border border-white/5 bg-dark-accent/60
        hover:border-neon/20 hover:bg-dark-accent
        transition-all duration-200 active:scale-[0.98] text-left
      `;
      btn.innerHTML = `
        <div class="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/5 flex items-center justify-center group-hover:border-neon/20 transition-colors">
          ${iconFn('w-4 h-4 text-gray-500 group-hover:text-neon/70 transition-colors')}
        </div>
        <span class="text-sm text-gray-300 group-hover:text-white transition-colors">${escapeHTML(peer.deviceName)}</span>
        <svg class="w-4 h-4 ml-auto text-gray-600 group-hover:text-neon/50 transition-colors" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M9 5l7 7-7 7"/></svg>
      `;
      btn.addEventListener('click', () => onSelect(peer.peerCode));
      list.appendChild(btn);
    });

    overlay.appendChild(list);
  }

  return overlay;
}

// ── State C: Awaiting approval ───────────────────────────────────────────

function renderAwaitingApproval(deviceName: string, onCancel: () => void, phase: 'requesting' | 'establishing' | 'slow' | 'local-network'): HTMLElement {
  const wrap = document.createElement('div');
  wrap.className = 'flex flex-col items-center gap-3 py-4 animate-fade-in';

  let statusText: string;
  let helpText: string;

  switch (phase) {
    case 'establishing':
      statusText = `Establishing secure connection with <span class="text-neon">${escapeHTML(deviceName)}</span>...`;
      helpText = 'Setting up encrypted channel';
      break;
    case 'slow':
      // RU3: intermediate timeout feedback - still trying, not failed yet
      statusText = `Still connecting to <span class="text-neon">${escapeHTML(deviceName)}</span>...`;
      helpText = 'This is taking longer than usual - the other device may be slow to respond';
      break;
    case 'local-network':
      statusText = `Chrome needs permission to reach <span class="text-neon">${escapeHTML(deviceName)}</span>`;
      helpText = 'Allow local network access to start the secure connection';
      break;
    default:
      statusText = `Waiting for <span class="text-neon">${escapeHTML(deviceName)}</span> to accept...`;
      helpText = 'The other device will be asked to confirm';
  }

  wrap.innerHTML = `
    <div class="relative flex items-center justify-center w-10 h-10">
      <div class="absolute w-10 h-10 rounded-full bg-neon/5 animate-ping"></div>
      <div class="absolute w-6 h-6 rounded-full bg-neon/10 animate-pulse"></div>
      <div class="w-3 h-3 rounded-full bg-neon/40"></div>
    </div>
    <div class="text-center space-y-1">
      <p class="text-sm text-white/80">${statusText}</p>
      <p class="text-xs text-gray-500">${helpText}</p>
    </div>
  `;
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'text-xs text-gray-500 hover:text-white/80 transition-colors mt-1';
  cancelBtn.textContent = 'Cancel';
  cancelBtn.addEventListener('click', onCancel);
  wrap.appendChild(cancelBtn);
  return wrap;
}

// ── State D: Incoming request ────────────────────────────────────────────

function renderIncomingRequest(
  deviceName: string,
  deviceType: string,
  onAccept: () => void,
  onDecline: () => void,
): HTMLElement {
  const iconFn = deviceIconMap[deviceType] || icons.laptop;
  const wrap = document.createElement('div');
  wrap.className = 'flex flex-col items-center gap-4 py-4 animate-fade-in';
  wrap.innerHTML = `
    <div class="w-12 h-12 rounded-xl bg-neon/10 border border-neon/20 flex items-center justify-center">
      ${iconFn('w-6 h-6 text-neon')}
    </div>
    <div class="text-center space-y-1">
      <p class="text-sm font-medium text-white"><span class="text-neon">${escapeHTML(deviceName)}</span> wants to connect</p>
      <p class="text-xs text-gray-500">Accept to start sharing files</p>
    </div>
  `;

  const btnRow = document.createElement('div');
  btnRow.className = 'flex gap-2 w-full max-w-xs';

  const declineBtn = document.createElement('button');
  declineBtn.className = 'flex-1 px-4 py-2 rounded-md border border-white/10 text-sm text-gray-400 hover:text-white hover:bg-white/5 transition-colors';
  declineBtn.textContent = 'Decline';
  declineBtn.addEventListener('click', onDecline);

  const acceptBtn = document.createElement('button');
  acceptBtn.className = 'flex-1 px-4 py-2 rounded-md bg-neon text-black text-sm font-medium hover:bg-neon/90 transition-colors';
  acceptBtn.textContent = 'Accept';
  acceptBtn.addEventListener('click', onAccept);

  btnRow.append(declineBtn, acceptBtn);
  wrap.appendChild(btnRow);
  return wrap;
}

// ── State E: Connected ───────────────────────────────────────────────────

function renderConnected(
  device: DiscoveredDevice,
  onDisconnect: () => void,
): HTMLElement {
  const iconFn = deviceIconMap[device.deviceType] || icons.laptop;

  const row = document.createElement('div');
  row.className = 'flex items-center justify-between py-2.5 px-3.5 rounded-md border border-neon/20 bg-neon/[0.03] animate-fade-in';
  row.innerHTML = `
    <div class="flex items-center gap-2.5 min-w-0">
      ${iconFn('w-4 h-4 text-neon flex-shrink-0')}
      <span class="text-sm text-white/80 truncate">${escapeHTML(device.deviceName)}</span>
    </div>
  `;

  const disconnectBtn = document.createElement('button');
  disconnectBtn.className = 'shrink-0 ml-3 text-xs text-gray-500 hover:text-white/80 transition-colors';
  disconnectBtn.textContent = 'Disconnect';
  disconnectBtn.addEventListener('click', () => {
    if (confirm(`Disconnect from ${device.deviceName}?`)) {
      onDisconnect();
    }
  });
  row.appendChild(disconnectBtn);

  return row;
}

// ── Main Component ───────────────────────────────────────────────────────

export function createDeviceDiscovery(
  onSelectPeer: (code: string) => void,
  onDisconnect: () => void,
  onAcceptRequest: () => void,
  onDeclineRequest: () => void,
  onCancelRequest: () => void,
): HTMLElement {
  const container = document.createElement('div');

  function render() {
    const { peers, connectingTo, isConnected, connectedDevice, incomingRequest, showDeviceList } = store.getState();

    container.innerHTML = '';

    // Priority order: connected > incoming request > awaiting approval > device list > button
    if (isConnected && connectedDevice) {
      container.appendChild(renderConnected(connectedDevice, onDisconnect));
    } else if (incomingRequest) {
      container.appendChild(renderIncomingRequest(
        incomingRequest.deviceName,
        incomingRequest.deviceType,
        onAcceptRequest,
        onDeclineRequest,
      ));
    } else if (connectingTo) {
      const peer = peers.find(p => p.peerCode === connectingTo);
      const name = peer?.deviceName || 'device';
      const { connectingPhase } = store.getState();
      container.appendChild(renderAwaitingApproval(name, onCancelRequest, connectingPhase ?? 'requesting'));
    } else if (showDeviceList) {
      container.appendChild(renderDeviceList(
        peers,
        onSelectPeer,
        () => store.setState({ showDeviceList: false }),
      ));
    } else {
      container.appendChild(renderDevicesButton(
        peers.length,
        () => store.setState({ showDeviceList: true }),
      ));
    }
  }

  store.subscribe(render);
  render();
  return container;
}
