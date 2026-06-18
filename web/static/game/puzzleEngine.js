// puzzleEngine.js — 12×12 word search grid generator + match detection

const SIZE = 12;
const DIRS = [[0,1],[1,0],[1,1],[-1,1]]; // right, down, diag-DR, diag-UR

export function createPuzzle(stage) {
  const words = stage.words.map(w => w.word.toUpperCase());
  const grid = Array.from({ length: SIZE }, () => Array(SIZE).fill(null));
  const placements = [];

  for (const word of words) {
    placeWord(grid, word, placements);
  }

  fillRandom(grid);

  return { grid, words, placements, SIZE };
}

function placeWord(grid, word, placements) {
  let attempts = 0;
  while (attempts++ < 150) {
    const [dr, dc] = DIRS[Math.floor(Math.random() * DIRS.length)];
    const r0 = Math.floor(Math.random() * SIZE);
    const c0 = Math.floor(Math.random() * SIZE);

    if (!canPlace(grid, word, r0, c0, dr, dc)) continue;

    const cells = [];
    for (let i = 0; i < word.length; i++) {
      const r = r0 + i * dr;
      const c = c0 + i * dc;
      grid[r][c] = word[i];
      cells.push({ r, c });
    }
    placements.push({ word, cells, found: false });
    return;
  }
  // If placement fails after 150 attempts, skip word (rare)
  console.warn(`[puzzleEngine] Could not place word: ${word}`);
}

function canPlace(grid, word, r0, c0, dr, dc) {
  for (let i = 0; i < word.length; i++) {
    const r = r0 + i * dr;
    const c = c0 + i * dc;
    if (r < 0 || r >= SIZE || c < 0 || c >= SIZE) return false;
    const cell = grid[r][c];
    if (cell && cell !== word[i]) return false;
  }
  return true;
}

function fillRandom(grid) {
  for (let r = 0; r < SIZE; r++)
    for (let c = 0; c < SIZE; c++)
      if (!grid[r][c])
        grid[r][c] = String.fromCharCode(65 + Math.floor(Math.random() * 26));
}

export function checkSelection(puzzle, cells) {
  if (cells.length < 2) return null;
  const word = cells.map(({ r, c }) => puzzle.grid[r][c]).join('');
  const reversed = word.split('').reverse().join('');
  return puzzle.placements.find(p =>
    !p.found && (p.word === word || p.word === reversed)
  ) || null;
}
