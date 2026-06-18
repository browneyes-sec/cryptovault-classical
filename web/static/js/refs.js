(function() {
    const container = document.getElementById('refs-container');

    const references = {
        'Classical Cryptography': [
            { title: 'The Codebreakers', authors: 'Kahn, D.', source: 'Scribner, 1996', note: 'Comprehensive history of secret communication' },
            { title: 'The Code Book', authors: 'Singh, S.', source: 'Anchor, 2000', note: 'Accessible introduction for general readers' },
            { title: 'Introduction to Cryptography with Coding Theory', authors: 'Trappe, W. & Washington, L.', source: '2nd ed., Pearson, 2006', note: 'Textbook with mathematical foundations' },
            { title: 'Cryptography: Theory and Practice', authors: 'Stinson, D.R.', source: '3rd ed., CRC Press, 2005', note: 'Standard graduate textbook' },
            { title: 'Introduction to Modern Cryptography', authors: 'Katz, J. & Lindell, Y.', source: '2nd ed., CRC Press, 2015', note: 'Definitive modern reference' },
        ],
        'Cipher-Specific References': [
            { title: 'Traiffé Chiffres', authors: 'Vigenère, B.', source: '1586', note: 'Original Vigenère cipher description' },
            { title: 'La Cryptographie Militaire', authors: 'Kerckhoffs, A.', source: 'Journal des Sciences Militaires, 1883', note: 'Kerckhoffs\'s principle' },
            { title: 'The Cryptography of Apostolic Constitutions', authors: 'Hill, L.S.', source: 'American Mathematical Monthly, 1929', note: 'Hill cipher original paper' },
            { title: 'The War of the Ciphers', authors: 'Friedman, W.F.', source: '1937', note: 'ADFGVX cipher analysis' },
            { title: 'De Furtivis Literarum Notis', authors: 'Porta, G.B.', source: '1563', note: 'Porta cipher original work' },
        ],
        'Modern Cryptography': [
            { title: 'New Directions in Cryptography', authors: 'Diffie, W. & Hellman, M.E.', source: 'IEEE Trans. IT, 22(6), 1976', note: 'Foundational public-key crypto paper' },
            { title: 'A Method for Obtaining Digital Signatures and Public-Key Cryptosystems', authors: 'Rivest, R.L., Shamir, A. & Adleman, L.', source: 'CACM, 21(2), 1978', note: 'RSA original paper' },
            { title: 'Communication Theory of Secrecy Systems', authors: 'Shannon, C.E.', source: 'Bell System Technical Journal, 28(4), 1949', note: 'Information-theoretic security foundation' },
        ],
        'Open Source & Education': [
            { title: 'Free Software, Free Society', authors: 'Stallman, R.', source: 'GNU Press, 2002', note: 'Philosophy of free software' },
            { title: 'The Wealth of Networks', authors: 'Benkler, Y.', source: 'Yale University Press, 2006', note: 'Networked information economy' },
            { title: 'Code: Version 2.0', authors: 'Lessig, L.', source: 'Basic Books, 2006', note: 'Code as law and governance' },
            { title: 'Data and Goliath', authors: 'Schneier, B.', source: 'W.W. Norton, 2015', note: 'Surveillance and privacy' },
        ],
        'Standards & Specifications': [
            { title: 'NIST SP 800-57 Part 1 Rev. 5', authors: 'National Institute of Standards and Technology', source: '2020', note: 'Key management recommendations' },
            { title: 'FIPS 197: Advanced Encryption Standard', authors: 'NIST', source: '2001', note: 'AES specification' },
            { title: 'FIPS 198-1: HMAC', authors: 'NIST', source: '2008', note: 'HMAC specification' },
            { title: 'RFC 2104: HMAC', authors: 'Krawczyk, H., Bellare, M. & Canetti, R.', source: '1997', note: 'HMAC Internet standard' },
            { title: 'Semantic Versioning 2.0.0', authors: 'Preston-Werner, T.', source: 'semver.org', note: 'Versioning specification' },
            { title: 'Keep a Changelog', authors: 'Ciole, T.', source: 'keepachangelog.com', note: 'Changelog format' },
        ],
    };

    function renderRefs() {
        container.innerHTML = '';
        for (const [group, refs] of Object.entries(references)) {
            const groupDiv = document.createElement('div');
            groupDiv.className = 'ref-group';
            groupDiv.innerHTML = `<h3>${group}</h3>`;
            refs.forEach(ref => {
                const item = document.createElement('div');
                item.className = 'ref-item';
                item.innerHTML = `
                    <div class="ref-title">${ref.title}</div>
                    <div class="ref-authors">${ref.authors}</div>
                    <div class="ref-source">${ref.source}</div>
                    ${ref.note ? `<div class="ref-note"><em>${ref.note}</em></div>` : ''}
                `;
                groupDiv.appendChild(item);
            });
            container.appendChild(groupDiv);
        }
    }

    router.register('refs', renderRefs);
})();
