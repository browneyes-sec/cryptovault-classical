class Router {
    constructor() {
        this.routes = {};
        this.currentTab = 'cipher';
        window.addEventListener('hashchange', () => this.route());
    }

    register(name, handler) {
        this.routes[name] = handler;
    }

    route() {
        const hash = location.hash.slice(1) || 'cipher';
        this.currentTab = hash;
        document.querySelectorAll('.tab-panel').forEach(panel => {
            const isTarget = panel.id === `${hash}-section`;
            panel.classList.toggle('active', isTarget);
            panel.hidden = !isTarget;
        });
        document.querySelectorAll('.nav-tab').forEach(tab => {
            const isActive = tab.dataset.tab === hash;
            tab.classList.toggle('active', isActive);
            tab.setAttribute('aria-selected', isActive);
        });
        if (this.routes[hash]) this.routes[hash]();
    }
}

async function api(path, options = {}) {
    const res = await fetch(path, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options,
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
}

function show(el) { el.classList.remove('hidden'); el.hidden = false; }
function hide(el) { el.classList.add('hidden'); el.hidden = true; }

function initNav() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            location.hash = tab.dataset.tab;
        });
    });
}

const router = new Router();
let islandInitialized = false;

router.register('island', async () => {
  if (!islandInitialized) {
    islandInitialized = true;
    const { initIsland } = await import('/game/app.js');
    const container = document.getElementById('island-container');
    if (container) initIsland(container);
  }
});

document.addEventListener('DOMContentLoaded', () => {
    initNav();
    router.route();
});
