import { getAllSources } from './source-registry.js';
import { getApiKey, setApiKey } from './settings.js';

let currentStep = 0;
let sources = [];

const modal = () => document.getElementById('wizard-modal');
const body = () => document.getElementById('wizard-body');
const prevBtn = () => document.getElementById('wizard-prev');
const nextBtn = () => document.getElementById('wizard-next');
const dotsContainer = () => document.getElementById('wizard-dots');
const closeBtn = () => document.getElementById('wizard-close');

export function initWizard() {
  sources = getAllSources();
  
  if (closeBtn()) {
    closeBtn().addEventListener('click', closeWizard);
  }
  if (prevBtn()) {
    prevBtn().addEventListener('click', goPrev);
  }
  if (nextBtn()) {
    nextBtn().addEventListener('click', goNext);
  }

  // Automatically launch if not completed
  if (!localStorage.getItem('glinthaven_wizard_complete')) {
    setTimeout(() => launchWizard(false), 500);
  }
}

export function launchWizard(force = true) {
  if (!force && localStorage.getItem('glinthaven_wizard_complete')) return;
  
  currentStep = 0;
  if (modal()) {
    modal().classList.remove('hidden');
    renderStep();
  }
}

export function closeWizard() {
  localStorage.setItem('glinthaven_wizard_complete', 'true');
  if (modal()) modal().classList.add('hidden');
  const terminalInput = document.getElementById('terminal-input');
  if (terminalInput) terminalInput.focus();
}

async function goNext() {
  if (nextBtn().disabled) return;

  const input = body().querySelector('.setting-input');
  
  if (input && input.value.trim()) {
    const src = sources[currentStep];
    if (typeof src.testAuth === 'function') {
      const originalText = nextBtn().textContent;
      nextBtn().textContent = 'Testing...';
      nextBtn().disabled = true;
      try {
        await src.testAuth(input.value.trim());
      } catch (e) {
        nextBtn().textContent = originalText;
        nextBtn().disabled = false;
        
        let errEl = body().querySelector('#wizard-step-error');
        if (!errEl) {
          errEl = document.createElement('p');
          errEl.id = 'wizard-step-error';
          errEl.className = 'term-warning';
          errEl.style.marginTop = 'var(--sp-sm)';
          input.parentNode.appendChild(errEl);
        }
        errEl.textContent = '❌ ' + e.message;
        input.focus();
        return;
      }
      nextBtn().disabled = false;
      nextBtn().textContent = originalText;
    }
  }

  saveCurrentInput();
  if (currentStep < sources.length - 1) {
    currentStep++;
    renderStep();
  } else {
    closeWizard();
  }
}

function goPrev() {
  saveCurrentInput();
  if (currentStep > 0) {
    currentStep--;
    renderStep();
  }
}

function saveCurrentInput() {
  const input = body().querySelector('.setting-input');
  if (input) {
    setApiKey(input.dataset.source, input.value);
  }
}

function renderStep() {
  const src = sources[currentStep];
  const currentKey = getApiKey(src.id);
  const requiredLabel = src.requiresKey ? 'required' : 'optional';

  body().innerHTML = `
    <div style="animation: fadeIn 0.3s var(--ease-out)">
      <h3 style="margin-bottom: var(--sp-sm); color: var(--cyan); font-family: var(--font-mono)">${src.name} <span style="font-size:0.7em; color:var(--text-muted); font-weight:normal;">— ${src.category || 'Source'}</span></h3>
      <p style="margin-bottom: var(--sp-md); color: var(--text-secondary); line-height: 1.5; font-size: 0.9rem;">
        This source provides intelligence for: <strong>${src.supportedTypes.join(', ')}</strong>.
      </p>
      <p class="setting-hint" style="margin-bottom: var(--sp-sm)">
        API Key is <strong>${requiredLabel}</strong>. Free tier: ${src.rateLimit}.<br/>
        <a href="${src.signupUrl}" target="_blank" rel="noopener" style="display:inline-block; margin-top:0.5em;">Get a free key →</a>
      </p>
      <input class="setting-input" type="password" placeholder="Paste your ${src.name} API key (or skip)…" data-source="${src.id}" value="${currentKey}" style="margin-top: var(--sp-sm)" autocomplete="off" />
    </div>
  `;

  // Update dots
  dotsContainer().innerHTML = sources.map((_, i) => 
    `<div class="wizard-dot ${i === currentStep ? 'active' : ''}"></div>`
  ).join('');

  // Update buttons
  prevBtn().style.visibility = currentStep === 0 ? 'hidden' : 'visible';
  nextBtn().textContent = currentStep === sources.length - 1 ? 'Finish' : 'Next';

  const input = body().querySelector('input');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        goNext();
      }
    });
    setTimeout(() => input.focus(), 100);
  }
}
