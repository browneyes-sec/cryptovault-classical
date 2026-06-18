(function() {
    const textArea = document.getElementById('analysis-text');
    const methodSelect = document.getElementById('analysis-method');
    const submitBtn = document.getElementById('analysis-submit');
    const resultArea = document.getElementById('analysis-result');

    submitBtn.addEventListener('click', async () => {
        const text = textArea.value.trim();
        const method = methodSelect.value;

        if (!text) { alert('Please enter text to analyze.'); return; }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Analyzing...';

        try {
            const endpoint = `/api/analysis/${method}`;
            const result = await api(endpoint, {
                method: 'POST',
                body: JSON.stringify({ text }),
            });

            resultArea.innerHTML = '';

            if (method === 'frequency') {
                renderFrequency(result);
            } else if (method === 'index-of-coincidence') {
                renderIoC(result);
            } else if (method === 'kasiski') {
                renderKasiski(result);
            } else if (method === 'brute-force') {
                renderBruteForce(result);
            }

            show(resultArea);
        } catch (e) {
            resultArea.innerHTML = `<div class="lab-result incorrect">Error: ${e.message}</div>`;
            show(resultArea);
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Analyze';
        }
    });

    function renderFrequency(data) {
        const maxPct = Math.max(...data.frequencies.map(f => f.percentage), 1);

        let html = '<h3>Frequency Analysis</h3>';
        html += `<p><strong>Chi-squared:</strong> ${data.chi_squared} &nbsp;|&nbsp; <strong>IoC:</strong> ${data.index_of_coincidence} &nbsp;|&nbsp; <strong>Classification:</strong> ${data.classification}</p>`;
        html += '<div class="freq-chart">';
        data.frequencies.forEach(f => {
            const height = Math.max((f.percentage / maxPct) * 100, 1);
            html += `<div class="freq-bar-wrapper"><div class="freq-bar" style="height:${height}%" title="${f.letter}: ${f.count} (${f.percentage}%)"></div><div class="freq-label">${f.letter}</div></div>`;
        });
        html += '</div>';

        html += '<h4>Frequency Table</h4>';
        html += '<table><thead><tr><th>Letter</th><th>Count</th><th>%</th></tr></thead><tbody>';
        data.frequencies.filter(f => f.count > 0).forEach(f => {
            html += `<tr><td>${f.letter}</td><td>${f.count}</td><td>${f.percentage}%</td></tr>`;
        });
        html += '</tbody></table>';

        resultArea.innerHTML = html;
    }

    function renderIoC(data) {
        let html = '<h3>Index of Coincidence</h3>';
        html += `<p><strong>IoC:</strong> ${data.index_of_coincidence}</p>`;
        html += `<p><strong>Classification:</strong> ${data.classification}</p>`;
        html += `<p><strong>Expected (English):</strong> ${data.expected_english}</p>`;
        html += `<p><strong>Expected (Random):</strong> ${data.expected_random}</p>`;

        const ioc = data.index_of_coincidence;
        let interpretation;
        if (Math.abs(ioc - data.expected_english) < 0.005) {
            interpretation = 'IoC close to English suggests monoalphabetic substitution.';
        } else if (Math.abs(ioc - data.expected_random) < 0.005) {
            interpretation = 'IoC close to random suggests polyalphabetic cipher or random text.';
        } else {
            interpretation = 'IoC between English and random — could be a polyalphabetic cipher with short key.';
        }
        html += `<p><em>${interpretation}</em></p>`;

        resultArea.innerHTML = html;
    }

    function renderKasiski(data) {
        let html = '<h3>Kasiski Examination</h3>';
        html += `<p><strong>Estimated key length:</strong> ${data.estimated_key_length}</p>`;
        if (data.recovered_key) {
            html += `<p><strong>Recovered key:</strong> <span class="mono-block">${data.recovered_key}</span></p>`;
        }

        if (data.repeated_sequences && data.repeated_sequences.length > 0) {
            html += '<h4>Repeated Sequences</h4>';
            html += '<table><thead><tr><th>Sequence</th><th>Count</th><th>Positions</th></tr></thead><tbody>';
            data.repeated_sequences.forEach(s => {
                html += `<tr><td class="mono-block">${s.sequence}</td><td>${s.count}</td><td>${s.positions.join(', ')}</td></tr>`;
            });
            html += '</tbody></table>';
        }

        resultArea.innerHTML = html;
    }

    function renderBruteForce(data) {
        let html = '<h3>Brute Force Results</h3>';
        if (data.results && data.results.length > 0) {
            html += '<table><thead><tr><th>Key</th><th>Confidence</th><th>Plaintext</th></tr></thead><tbody>';
            data.results.forEach(r => {
                html += `<tr><td class="mono-block">${r.key}</td><td>${(r.confidence * 100).toFixed(1)}%</td><td class="mono-block">${r.plaintext}</td></tr>`;
            });
            html += '</tbody></table>';
        } else {
            html += '<p>No results found. The cipher may not support brute-force.</p>';
        }

        resultArea.innerHTML = html;
    }
})();
