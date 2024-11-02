fetch('http://localhost:2000/csp-violation-report', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/text'
    },
    body: JSON.stringify({
        'csp-report': {
            'document-uri': 'http://example.com',
            'referrer': 'http://example.com',
            'blocked-uri': 'http://example.com/script.js',
            'violated-directive': 'script-src',
            'original-policy': 'default-src \'self\''
        }
    })
});
