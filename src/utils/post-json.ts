import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';

// Plain JSON POST; http for tests, https in production (same pattern as
// connect's postConnect — the URL's protocol picks the lib).
export function postJson<T>(url: string, body: unknown, bearer?: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const u = new URL(url);
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.request(
      {
        method: 'POST',
        hostname: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
          ...(bearer && { Authorization: `Bearer ${bearer}` }),
        },
        timeout: 15000,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          const code = res.statusCode ?? 0;
          if (code >= 200 && code < 300) {
            try {
              resolve(JSON.parse(data) as T);
            } catch {
              reject(new Error('Unexpected response from the server.'));
            }
          } else {
            reject(new Error(`Server returned HTTP ${code}.`));
          }
        });
      }
    );
    req.on('error', (e) => reject(e));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Connection timed out.'));
    });
    req.write(payload);
    req.end();
  });
}
