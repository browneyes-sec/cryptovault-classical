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
};

export function initIsland(container) {
  state.currentStage = null;
  state.currentPuzzle = null;
  container.innerHTML = '';

  // Island header
  const header = document.createElement('div');
  header.className = 'island-header';
  header.innerHTML = `
    <h2 class="island-title">Crypto Island</h2>
    <p class="island-subtitle">Tap a location to begin</p>
    <div class="island-score">Score: ${state.session.totalScore}</div>
  `;
  container.appendChild(header);

  // Island map (CSS-generated)
  const map = document.createElement('div');
  map.className = 'island-map';
  map.innerHTML = `<div class="island-terrain"></div>`;
  container.appendChild(map);

  // Hotspots
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
  renderPuzzle(container);
}

function renderPuzzle(container) {
  const stage = state.currentStage;
  const puzzle = state.currentPuzzle;
  container.innerHTML = '';

  // Puzzle header
  const header = document.createElement('div');
  header.className = 'puzzle-header';
  header.innerHTML = `
    <button class="btn-back" aria-label="Back to island">← Island</button>
    <h2 class="puzzle-title" style="color:${stage.color}">${stage.name}</h2>
    <div class="puzzle-score">Score: ${state.session.totalScore}</div>
  `;
  header.querySelector('.btn-back').addEventListener('click', () => initIsland(container));
  container.appendChild(header);

  // Puzzle description
  const desc = document.createElement('p');
  desc.className = 'puzzle-description';
  desc.textContent = stage.description;
  container.appendChild(desc);

  // Main layout
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
          // Only add adjacent cells
          if (Math.abs(r - last.r) <= 1 && Math.abs(c - last.c) <= 1 && (r !== last.r || c !== last.c)) {
            // Check if already selected (avoid duplicates)
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

  // Word list
  const wordList = document.createElement('div');
  wordList.className = 'puzzle-wordlist';
  wordList.innerHTML = '<h3>Words to Find</h3>';

  for (const entry of stage.words) {
    const li = document.createElement('button');
    li.className = 'word-item';
    li.dataset.word = entry.word;

    const placement = puzzle.placements.find(p => p.word === entry.word);
    if (placement && placement.found) {
      li.classList.add('found');
    }

    li.innerHTML = `
      <span class="word-text">${entry.word}</span>
      <span class="word-cipher">${stage.cipher.toUpperCase()}</span>
    `;
    li.addEventListener('click', () => showHintModal(entry, stage, container));
    wordList.appendChild(li);
  }

  layout.appendChild(wordList);
  container.appendChild(layout);
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

    // Highlight found word
    for (const { r, c } of match.cells) {
      const cell = document.querySelector(`.grid-cell[data-r="${r}"][data-c="${c}"]`);
      if (cell) cell.classList.add('found');
    }

    // Mark word in list
    const wordItem = document.querySelector(`.word-item[data-word="${match.word}"]`);
    if (wordItem) wordItem.classList.add('found');

    // Update score
    const scoreEl = document.querySelector('.puzzle-score');
    if (scoreEl) scoreEl.textContent = `Score: ${state.session.totalScore}`;

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

function showHintModal(wordEntry, stage, container) {
  // Remove existing modal
  const existing = document.getElementById('modal-hint');
  if (existing) existing.remove();

  const ciphertext = stage.hintKey === null
    ? CiphersLite[stage.cipher](wordEntry.word)
    : Array.isArray(stage.hintKey)
      ? CiphersLite[stage.cipher](wordEntry.word, ...stage.hintKey)
      : CiphersLite[stage.cipher](wordEntry.word, stage.hintKey);

  const keyHint = buildKeyHint(stage.cipher, stage.hintKey);

  const modal = document.createElement('div');
  modal.id = 'modal-hint';
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-content">
      <h3>Decode the ${stage.cipher.toUpperCase()} Challenge</h3>
      <p class="hint-ciphertext">${ciphertext}</p>
      <p class="hint-key">${keyHint}</p>
      <p class="hint-clue">${wordEntry.hint}</p>
      <input type="text" id="hint-answer" class="hint-input" placeholder="Type the decoded word" autocomplete="off" />
      <div class="hint-actions">
        <button id="btn-submit-hint" class="btn-primary">Submit</button>
        <button id="btn-close-hint" class="btn-secondary">Cancel</button>
      </div>
      <p class="hint-error hidden"></p>
    </div>
  `;

  document.body.appendChild(modal);

  const input = modal.querySelector('#hint-answer');
  const error = modal.querySelector('.hint-error');
  input.focus();

  modal.querySelector('#btn-submit-hint').addEventListener('click', () => {
    const answer = input.value.trim().toUpperCase();
    if (answer === wordEntry.word) {
      modal.remove();
      // Auto-highlight the word in the grid
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

        const wordItem = document.querySelector(`.word-item[data-word="${wordEntry.word}"]`);
        if (wordItem) wordItem.classList.add('found');

        const scoreEl = document.querySelector('.puzzle-score');
        if (scoreEl) scoreEl.textContent = `Score: ${state.session.totalScore}`;

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
    } else {
      error.textContent = 'Not quite — try again!';
      error.classList.remove('hidden');
      input.value = '';
      input.focus();
    }
  });

  modal.querySelector('#btn-close-hint').addEventListener('click', () => modal.remove());
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });
}

function buildKeyHint(cipher, key) {
  if (cipher === 'caesar')    return `Hint: Shift = ${key}`;
  if (cipher === 'atbash')    return `Hint: No key — A↔Z mirror`;
  if (cipher === 'vigenere')  return `Hint: Key = "${key}"`;
  return '';
}
