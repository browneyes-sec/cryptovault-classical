// islandModel.js — Static game structure: stages, words, cipher metadata
// Adding a new stage = adding data only. Engine logic unchanged.

export const ISLAND_STAGES = [
  {
    id: 'beach',
    name: 'Beach of Shifts',
    description: 'Learn the Caesar cipher — each letter shifts by a fixed amount.',
    cipher: 'caesar',
    difficulty: 'easy',
    hintKey: 3,
    words: [
      { word: 'CAESAR',   hint: 'Roman general who used shift ciphers' },
      { word: 'SHIFT',    hint: 'Each letter moves by this amount' },
      { word: 'CODE',     hint: 'Secret form of writing' },
      { word: 'ANCIENT',  hint: 'Very old — like these ciphers' },
      { word: 'ROME',     hint: 'Capital of the Roman Empire' },
    ],
    hotspot: { x: 18, y: 62 },
    color: '#4a9eff',
  },
  {
    id: 'forest',
    name: 'Forest of Mirrors',
    description: 'Discover the Atbash cipher — the alphabet reflects on itself.',
    cipher: 'atbash',
    difficulty: 'easy',
    hintKey: null,
    words: [
      { word: 'ATBASH',   hint: 'Hebrew word for "alphabet"' },
      { word: 'MIRROR',   hint: 'Reflects — like this cipher' },
      { word: 'ALPHABET', hint: 'The letter system this cipher transforms' },
      { word: 'REVERSE',  hint: 'What Atbash does to the alphabet' },
      { word: 'ZENITH',   hint: 'Highest point — Atbash maps A to the end' },
    ],
    hotspot: { x: 42, y: 48 },
    color: '#2ecc71',
  },
  {
    id: 'cliffs',
    name: 'Cliffs of Keys',
    description: 'Master the Vigenère cipher — a keyword drives polyalphabetic substitution.',
    cipher: 'vigenere',
    difficulty: 'medium',
    hintKey: 'KEY',
    words: [
      { word: 'VIGENERE', hint: 'French diplomat who created this cipher' },
      { word: 'KEYWORD',  hint: 'The secret word that drives this cipher' },
      { word: 'CIPHER',   hint: 'Algorithm for encryption/decryption' },
      { word: 'SECRET',   hint: 'Hidden information — the goal of encryption' },
      { word: 'ROYAL',    hint: 'Relating to kings — like the cipher\'s history' },
    ],
    hotspot: { x: 72, y: 32 },
    color: '#e74c3c',
  },
];
