(function() {
    const container = document.getElementById('labs-container');

    const labs = [
        {
            id: 'caesar-fundamentals',
            title: 'Lab 1: Caesar Cipher Fundamentals',
            difficulty: 'beginner',
            description: 'Encrypt the word "HELLO" using the Caesar cipher with shift 3. What is the ciphertext?',
            hint: 'Each letter shifts forward by the key value in the alphabet.',
        },
        {
            id: 'vigenere-breaking',
            title: 'Lab 2: Breaking the Vigenère Cipher',
            difficulty: 'intermediate',
            description: 'Use Kasiski examination to determine the keyword used to encrypt a Vigenère ciphertext. The key is a common English word.',
            hint: 'Look for repeated trigrams in the ciphertext. The distance between repeats reveals the key length.',
        },
        {
            id: 'frequency-analysis',
            title: 'Lab 3: Frequency Analysis',
            difficulty: 'intermediate',
            description: 'Analyze the following ciphertext and determine what type of cipher was used. The answer should be one of: monoalphabetic, polyalphabetic, or transposition.',
            hint: 'Compare the letter frequency distribution to standard English. Single-alphabet substitution preserves frequency peaks.',
        },
        {
            id: 'playfair-cracking',
            title: 'Lab 4: Breaking the Playfair Cipher',
            difficulty: 'advanced',
            description: 'Use crib-dragging with common English digraphs (TH, HE, IN, ER) to recover the Playfair keyword. The keyword is a single English word.',
            hint: 'Start with the most common English digraph "TH" and try inserting it at different positions.',
        },
        {
            id: 'field-ciphers',
            title: 'Lab 5: WWI Field Cipher (ADFGVX)',
            difficulty: 'doctoral',
            description: 'Break an ADFGVX cipher by first reversing the columnar transposition, then decoding the ADFGVX substitution. What was the original plaintext message?',
            hint: 'The ADFGVX cipher has two stages: (1) columnar transposition, (2) 6x6 Polybius square lookup.',
        },
    ];

    function renderLabs() {
        container.innerHTML = '';
        labs.forEach(lab => {
            const card = document.createElement('div');
            card.className = 'lab-card';
            card.innerHTML = `
                <h3>${lab.title}</h3>
                <span class="difficulty ${lab.difficulty}">${lab.difficulty}</span>
                <p class="description">${lab.description}</p>
                <div class="form-row">
                    <label for="lab-answer-${lab.id}">Your Answer</label>
                    <input type="text" id="lab-answer-${lab.id}" placeholder="Enter your answer">
                </div>
                <button class="btn-primary lab-submit" data-lab="${lab.id}" type="button">Submit Answer</button>
                <div id="lab-result-${lab.id}" class="hidden"></div>
                <p class="hint" id="lab-hint-${lab.id}" class="hidden"></p>
            `;
            container.appendChild(card);
        });

        container.querySelectorAll('.lab-submit').forEach(btn => {
            btn.addEventListener('click', async () => {
                const labId = btn.dataset.lab;
                const input = document.getElementById(`lab-answer-${labId}`);
                const resultDiv = document.getElementById(`lab-result-${labId}`);
                const hintP = document.getElementById(`lab-hint-${labId}`);
                const answer = input.value.trim();

                if (!answer) { alert('Please enter an answer.'); return; }

                btn.disabled = true;
                btn.textContent = 'Checking...';

                try {
                    const result = await api(`/api/labs/${labId}/submit`, {
                        method: 'POST',
                        body: JSON.stringify({ answer, lab_id: labId }),
                    });

                    resultDiv.className = `lab-result ${result.correct ? 'correct' : 'incorrect'}`;
                    resultDiv.textContent = result.feedback;
                    resultDiv.classList.remove('hidden');

                    if (result.correct) {
                        hintP.textContent = '';
                        hintP.classList.add('hidden');
                    } else if (result.hint) {
                        hintP.textContent = 'Hint: ' + result.hint;
                        hintP.classList.remove('hidden');
                    }
                } catch (e) {
                    resultDiv.className = 'lab-result incorrect';
                    resultDiv.textContent = 'Error: ' + e.message;
                    resultDiv.classList.remove('hidden');
                } finally {
                    btn.disabled = false;
                    btn.textContent = 'Submit Answer';
                }
            });
        });
    }

    router.register('labs', renderLabs);
})();
