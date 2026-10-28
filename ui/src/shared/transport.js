// Production transport: same-origin requests to the host page (WHM index.cgi, cPanel index.live.php).
// The page URL carries cpsrvd's session prefix, so relative URLs stay inside the authenticated session.
// Returns the HTTP status and the parsed JSON body; the body is null when the reply is not JSON (a
// login page after the session expired) and the status is 0 for a redirect (also an expired session).
export async function send({ method, url, headers, body }) {
  const response = await fetch(url, {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'manual',
    headers,
    body,
  })
  const type = response.headers.get('Content-Type') || ''
  const json = type.includes('application/json') ? await response.json().catch(() => null) : null
  return { status: response.status, body: json }
}
