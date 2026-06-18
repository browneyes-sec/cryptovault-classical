// app.js — Island ↔ Puzzle game controller

import { ISLAND_STAGES } from './islandModel.js';
import { createPuzzle, checkSelection } from './puzzleEngine.js';
import { CiphersLite } from './ciphersLite.js';
import { loadSession, saveSession } from './sessionLite.js';

const state = {
  session: loadSession(),
  currentStage: null,
  currentPuzzle: null,
  selectedCells: [],
  isDragging: false,
  decodedWords: new Set(), // tracks which words have been decoded
};

export function initIsland(container) {
  state.currentStage = null;
  state.currentPuzzle = null;
  state.decodedWords.clear();
  container.innerHTML = '';

  const header = document.createElement('div');
  header.className = 'island-header';
  header.innerHTML = `
    <h2 class="island-title">Crypto Island</h2>
    <p class="island-subtitle">Tap a location to begin</p>
    <div class="island-score">Score: ${state.session.totalScore}</div>
  `;
  container.appendChild(header);

  const map = document.createElement('div');
  map.className = 'island-map';
  map.innerHTML = `<div class="island-terrain"></div>`;
  container.appendChild(map);

  const hotspots = document.createElement('div');
  hotspots.className = 'island-hotspots';

  for (const stage of ISLAND_STAGES) {
    const btn = document.createElement('button');
    btn.className = 'island-hotspot';
    btn.style.left = `${stage.hotspot.x}%`;
    btn.style.top = `${stage.hotspot.y}%`;
    btn.style.setProperty('--hotspot-color', stage.color);
    btn.setAttribute('aria-label', stage.name);

    const cleared = state.session.stagesCleared.includes(stage.id);
    if (cleared) btn.classList.add('cleared');

    btn.innerHTML = `
      <span class="hotspot-dot"></span>
      <span class="hotspot-label">${stage.name}</span>
    `;

    btn.addEventListener('click', () => startStage(stage, container));
    hotspots.appendChild(btn);
  }

  map.appendChild(hotspots);
  container.appendChild(header);
  container.appendChild(map);
}

function startStage(stage, container) {
  state.currentStage = stage;
  state.currentPuzzle = createPuzzle(stage);
  state.selectedCells = [];
  state.decodedWords.clear();
  renderPuzzle(container);
}

function renderPuzzle(container) {
  const stage = state.currentStage;
  const puzzle = state.currentPuzzle;
  container.innerHTML = '';

  // Header
  const header = document.createElement('div');
  header.className = 'puzzle-header';
  header.innerHTML = `
    <button class="btn-back" aria-label="Back to island">← Island</button>
    <h2 class="puzzle-title" style="color:${stage.color}">${stage.name}</h2>
    <div class="puzzle-score">Score: ${state.session.totalScore}</div>
  `;
  header.querySelector('.btn-back').addEventListener('click', () => initIsland(container));
  container.appendChild(header);

  // Description
  const desc = document.createElement('p');
  desc.className = 'puzzle-description';
  desc.textContent = stage.description;
  container.appendChild(desc);

  // Layout
  const layout = document.createElement('div');
  layout.className = 'puzzle-layout';

  // Grid
  const gridEl = document.createElement('div');
  gridEl.className = 'puzzle-grid';
  gridEl.style.setProperty('--grid-size', puzzle.SIZE);

  for (let r = 0; r < puzzle.SIZE; r++) {
    for (let c = 0; c < puzzle.SIZE; c++) {
      const cell = document.createElement('button');
      cell.className = 'grid-cell';
      cell.textContent = puzzle.grid[r][c];
      cell.dataset.r = r;
      cell.dataset.c = c;
      cell.setAttribute('aria-label', `Row ${r+1}, Col ${c+1}: ${puzzle.grid[r][c]}`);

      cell.addEventListener('mousedown', (e) => {
        e.preventDefault();
        state.isDragging = true;
        state.selectedCells = [{ r, c }];
        highlightCells();
      });
      cell.addEventListener('mouseenter', () => {
        if (state.isDragging) {
          const last = state.selectedCells[state.selectedCells.length - 1];
          if (Math.abs(r - last.r) <= 1 && Math.abs(c - last.c) <= 1 && (r !== last.r || c !== last.c)) {
            if (!state.selectedCells.some(s => s.r === r && s.c === c)) {
              state.selectedCells.push({ r, c });
              highlightCells();
            }
          }
        }
      });
      cell.addEventListener('mouseup', () => handleRelease(container));
      cell.addEventListener('touchstart', (e) => {
        e.preventDefault();
        state.isDragging = true;
        state.selectedCells = [{ r, c }];
        highlightCells();
      }, { passive: false });
      cell.addEventListener('touchmove', (e) => {
        e.preventDefault();
        const touch = e.touches[0];
        const el = document.elementFromPoint(touch.clientX, touch.clientY);
        if (el && el.dataset.r !== undefined) {
          const tr = parseInt(el.dataset.r);
          const tc = parseInt(el.dataset.c);
          const last = state.selectedCells[state.selectedCells.length - 1];
          if (Math.abs(tr - last.r) <= 1 && Math.abs(tc - last.c) <= 1 && (tr !== last.r || tc !== last.c)) {
            if (!state.selectedCells.some(s => s.r === tr && s.c === tc)) {
              state.selectedCells.push({ r: tr, c: tc });
              highlightCells();
            }
          }
        }
      }, { passive: false });
      cell.addEventListener('touchend', () => handleRelease(container));

      gridEl.appendChild(cell);
    }
  }
  layout.appendChild(gridEl);

  // Word list — CIPHERTEXT ONLY
  const wordList = document.createElement('div');
  wordList.className = 'puzzle-wordlist';
  wordList.innerHTML = '<h3>Decode & Find</h3>';

  for (const entry of stage.words) {
    const ciphertext = getCiphertext(entry.word, stage);

    const li = document.createElement('button');
    li.className = 'word-item';
    li.dataset.word = entry.word;

    const placement = puzzle.placements.find(p => p.word === entry.word);
    const isDecoded = state.decodedWords.has(entry.word);
    const isFound = placement && placement.found;

    if (isFound) li.classList.add('found');
    else if (isDecoded) li.classList.add('decoded');

    if (isFound) {
      li.innerHTML = `
        <span class="word-plain">${entry.word}</span>
        <span class="word-cipher">${stage.cipher.toUpperCase()}</span>
        <span class="word-status">✓</span>
      `;
    } else if (isDecoded) {
      li.innerHTML = `
        <span class="word-plain">${entry.word}</span>
        <span class="word-cipher">${stage.cipher.toUpperCase()}</span>
        <span class="word-status">Find it!</span>
      `;
    } else {
      li.innerHTML = `
        <span class="word-ciphertext">${ciphertext}</span>
        <span class="word-cipher">${stage.cipher.toUpperCase()}</span>
        <span class="word-status">🔒</span>
      `;
    }

    li.addEventListener('click', () => {
      if (isFound) return; // already found, no action
      showHintModal(entry, ciphertext, stage, container);
    });
    wordList.appendChild(li);
  }

  layout.appendChild(wordList);
  container.appendChild(layout);
}

function getCiphertext(word, stage) {
  return stage.hintKey === null
    ? CiphersLite[stage.cipher](word)
    : Array.isArray(stage.hintKey)
      ? CiphersLite[stage.cipher](word, ...stage.hintKey)
      : CiphersLite[stage.cipher](word, stage.hintKey);
}

function highlightCells() {
  const cells = document.querySelectorAll('.grid-cell');
  cells.forEach(cell => {
    const r = parseInt(cell.dataset.r);
    const c = parseInt(cell.dataset.c);
    const selected = state.selectedCells.some(s => s.r === r && s.c === c);
    cell.classList.toggle('selected', selected);
  });
}

function handleRelease(container) {
  state.isDragging = false;
  if (state.selectedCells.length < 2) {
    clearSelection();
    return;
  }

  const match = checkSelection(state.currentPuzzle, state.selectedCells);
  if (match) {
    match.found = true;
    const pts = 10 + state.currentStage.words.find(w => w.word === match.word).word.length;
    state.session.totalScore += pts;
    saveSession(state.session);

    for (const { r, c } of match.cells) {
      const cell = document.querySelector(`.grid-cell[data-r="${r}"][data-c="${c}"]`);
      if (cell) cell.classList.add('found');
    }

    const scoreEl = document.querySelector('.puzzle-score');
    if (scoreEl) scoreEl.textContent = `Score: ${state.session.totalScore}`;

    // Re-render word list to show found state
    renderPuzzle(container);

    // Check stage clear
    if (state.currentPuzzle.placements.every(p => p.found)) {
      if (!state.session.stagesCleared.includes(state.currentStage.id)) {
        state.session.stagesCleared.push(state.currentStage.id);
        saveSession(state.session);
      }
      setTimeout(() => {
        alert(`${state.currentStage.name} cleared! 🎉`);
        initIsland(container);
      }, 500);
    }
  }

  clearSelection();
}

function clearSelection() {
  state.selectedCells = [];
  document.querySelectorAll('.grid-cell.selected').forEach(c => c.classList.remove('selected'));
}

function showHintModal(wordEntry, ciphertext, stage, container) {
  const existing = document.getElementById('modal-hint');
  if (existing) existing.remove();

  const keyHint = buildKeyHint(stage.cipher, stage.hintKey);

  const modal = document.createElement('div');
  modal.id = 'modal-hint';
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-content">
      <h3>Decode the ${stage.cipher.toUpperCase()} Challenge</h3>

      <div class="hint-cipher-display">
        <span class="hint-cipher-label">Ciphertext</span>
        <span class="hint-ciphertext" id="hint-ct-text">${ciphertext}</span>
        <button id="btn-copy-ct" class="btn-copy" title="Copy ciphertext">📋 Copy</button>
      </div>

      <div class="hint-cipher-info">
        <span>Cipher: <strong>${stage.cipher.toUpperCase()}</strong></span>
        <span>${keyHint}</span>
      </div>

      <p class="hint-clue">💡 ${wordEntry.hint}</p>

      <input type="text" id="hint-answer" class="hint-input" placeholder="Type the decoded word" autocomplete="off" />
      <p class="hint-feedback hidden"></p>

      <div class="hint-actions">
        <button id="btn-submit-hint" class="btn-primary">Decode & Find</button>
        <button id="btn-close-hint" class="btn-secondary">Cancel</button>
      </div>
    </div>
  `;

  document.body.appendChild(modal);

  const input = modal.querySelector('#hint-answer');
  const feedback = modal.querySelector('.hint-feedback');
  input.focus();

  // Copy button
  modal.querySelector('#btn-copy-ct').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(ciphertext);
      const btn = modal.querySelector('#btn-copy-ct');
      btn.textContent = '✓ Copied';
      setTimeout(() => { btn.innerHTML = '📋 Copy'; }, 1500);
    } catch {
      // Fallback: select text in input
      input.value = ciphertext;
      input.select();
    }
  });

  // Submit
  modal.querySelector('#btn-submit-hint').addEventListener('click', () => {
    const answer = input.value.trim().toUpperCase();
    if (answer === wordEntry.word) {
      modal.remove();

      // Mark as decoded
      state.decodedWords.add(wordEntry.word);

      // Auto-find the word in the puzzle
      const placement = state.currentPuzzle.placements.find(p => p.word === wordEntry.word);
      if (placement && !placement.found) {
        placement.found = true;
        const pts = 10 + wordEntry.word.length;
        state.session.totalScore += pts;
        saveSession(state.session);

        for (const { r, c } of placement.cells) {
          const cell = document.querySelector(`.grid-cell[data-r="${r}"][data-c="${c}"]`);
          if (cell) cell.classList.add('found');
        }

        const scoreEl = document.querySelector('.puzzle-score');
        if (scoreEl) scoreEl.textContent = `Score: ${state.session.totalScore}`;
      }

      // Re-render word list
      renderPuzzle(container);

      // Check stage clear
      if (state.currentPuzzle.placements.every(p => p.found)) {
        if (!state.session.stagesCleared.includes(state.currentStage.id)) {
          state.session.stagesCleared.push(state.currentStage.id);
          saveSession(state.session);
        }
        setTimeout(() => {
          alert(`${state.currentStage.name} cleared! 🎉`);
          initIsland(container);
        }, 500);
      }
    } else {
      feedback.textContent = '✗ Not quite — try again!';
      feedback.className = 'hint-feedback hint-error-msg';
      input.value = '';
      input.focus();
    }
  });

  // Enter key submits
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      modal.querySelector('#btn-submit-hint').click();
    }
  });

  modal.querySelector('#btn-close-hint').addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
}

function buildKeyHint(cipher, key) {
  if (cipher === 'caesar')    return `Shift = ${key}`;
  if (cipher === 'atbash')    return 'No key — A↔Z mirror';
  if (cipher === 'vigenere')  return `Key = "${key}"`;
  return '';
}
