//everything inline single file for HTML and JS etc etc
export async function onRequest(context) {
    const { request } = context;
    const url = new URL(request.url);
  
    // Serve the HTML page on the root route.
    if (url.pathname === '/') {
      const html = `
        <!DOCTYPE html>
        <html>
          <head>
            <meta charset="UTF-8">
            <title>DMARC Checker</title>
            <style>
              body { font-family: sans-serif; margin: 2rem; }
              input, button { padding: 0.5rem; font-size: 1rem; }
            </style>
          </head>
          <body>
            <h1>DMARC Checker</h1>
            <form id="dmarcForm">
              <input type="text" name="domain" placeholder="Enter domain" required />
              <button type="submit">Check DMARC</button>
            </form>
            <pre id="result"></pre>
            <script>
              const form = document.getElementById('dmarcForm');
              form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const domain = form.domain.value;
                const res = await fetch('/api/check?domain=' + encodeURIComponent(domain));
                const data = await res.json();
                document.getElementById('result').textContent = JSON.stringify(data, null, 2);
              });
            </script>
          </body>
        </html>
      `;
      return new Response(html, { headers: { 'content-type': 'text/html' } });
    }
  
    // API endpoint for checking DMARC; this is a placeholder.
    if (url.pathname.startsWith('/api/check')) {
      const domain = url.searchParams.get('domain');
      const result = {
        domain: domain,
        message: `DMARC check for ${domain} not implemented yet.`,
      };
      return new Response(JSON.stringify(result, null, 2), {
        headers: { 'content-type': 'application/json' },
      });
    }
  
    return new Response('Not found', { status: 404 });
  }