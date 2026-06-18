(function() {
    const select = document.getElementById('cipher-select');
    const keyInput = document.getElementById('cipher-key');
    const cipherHelp = document.getElementById('cipher-help');
    const keyHelp = document.getElementById('key-help');
    const plaintextRow = document.getElementById('plaintext-row');
    const ciphertextRow = document.getElementById('ciphertext-row');
    const plaintextArea = document.getElementById('cipher-plaintext');
    const ciphertextArea = document.getElementById('cipher-ciphertext');
    const submitBtn = document.getElementById('cipher-submit');
    const resultArea = document.getElementById('cipher-result');
    const resultText = document.getElementById('cipher-result-text');
    const stepsList = document.getElementById('cipher-steps');

    let cipherData = {};

    async function loadCiphers() {
        try {
            const data = await api('/api/ciphers');
            cipherData = {};
            data.ciphers.forEach(c => { cipherData[c.name] = c; });
            select.innerHTML = '<option value="">Select a cipher...</option>';
            data.ciphers.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.name;
                opt.textContent = `${c.name} (${c.category})`;
                select.appendChild(opt);
            });
        } catch (e) {
            cipherHelp.textContent = 'Error loading ciphers: ' + e.message;
        }
    }

    select.addEventListener('change', () => {
        const c = cipherData[select.value];
        if (c) {
            cipherHelp.textContent = `${c.description} — Key type: ${c.key_type}`;
            keyHelp.textContent = c.breakable ? 'This cipher can be broken without the key.' : 'This cipher achieves perfect secrecy when used correctly.';
        } else {
            cipherHelp.textContent = '';
            keyHelp.textContent = '';
        }
    });

    document.querySelectorAll('input[name="cipher-action"]').forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'encrypt') {
                show(plaintextRow);
                hide(ciphertextRow);
            } else {
                hide(plaintextRow);
                show(ciphertextRow);
            }
        });
    });

    submitBtn.addEventListener('click', async () => {
        const cipher = select.value;
        const key = keyInput.value;
        const action = document.querySelector('input[name="cipher-action"]:checked').value;
        const plaintext = plaintextArea.value;
        const ciphertext = ciphertextArea.value;

        if (!cipher) { alert('Please select a cipher.'); return; }
        if (!key) { alert('Please enter a key.'); return; }
        if (action === 'encrypt' && !plaintext) { alert('Please enter plaintext.'); return; }
        if (action === 'decrypt' && !ciphertext) { alert('Please enter ciphertext.'); return; }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';

        try {
            const body = { cipher, key, action };
            if (action === 'encrypt') body.plaintext = plaintext;
            else body.ciphertext = ciphertext;

            const result = await api('/api/cipher', {
                method: 'POST',
                body: JSON.stringify(body),
            });

            resultText.textContent = result.result;
            stepsList.innerHTML = '';
            result.steps.forEach(step => {
                const li = document.createElement('li');
                li.textContent = step;
                stepsList.appendChild(li);
            });
            show(resultArea);
        } catch (e) {
            resultText.textContent = 'Error: ' + e.message;
            stepsList.innerHTML = '';
            show(resultArea);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Process';
        }
    });

    loadCiphers();
})();
