import { escapeHTML } from '../lib/sanitize.js';

let container: HTMLElement | null = null;

function getContainer(): HTMLElement {
  if (!container) {
    container = document.createElement('div');
    container.className = 'fixed bottom-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none';
    document.body.appendChild(container);
  }
  return container;
}

export function showToast(
  title: string,
  description?: string,
  variant: 'default' | 'destructive' = 'default',
  durationMs = 2000,
) {
  const toast = document.createElement('div');
  toast.className = `
    pointer-events-auto max-w-sm w-full rounded-lg border px-4 py-3 shadow-lg
    backdrop-blur-xl transition-all duration-300 animate-fade-up
    ${variant === 'destructive'
      ? 'bg-red-950/90 border-red-500/30 text-red-100'
      : 'bg-dark-accent/90 border-white/10 text-white'}
  `;

  toast.innerHTML = `
    <p class="text-sm font-medium">${escapeHTML(title)}</p>
    ${description ? `<p class="text-xs mt-0.5 opacity-70">${escapeHTML(description)}</p>` : ''}
  `;

  const parent = getContainer();
  parent.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(8px)';
    setTimeout(() => toast.remove(), 300);
  }, durationMs);
}
