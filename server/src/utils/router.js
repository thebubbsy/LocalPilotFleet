/**
 * LocalPilot Fleet — Zero-Dependency HTTP Router
 * server/src/utils/router.js
 */

export class Router {
  constructor() {
    this.routes = [];
    this.maxBodyBytes = 5 * 1024 * 1024; // 5 MB max body
  }

  add(method, pathPattern, handler) {
    const paramNames = [];
    // Convert :param to capture group ([^/]+)
    const regexPattern = pathPattern.replace(/:([a-zA-Z0-9_]+)/g, (_, name) => {
      paramNames.push(name);
      return '([^/]+)';
    });
    const regex = new RegExp(`^${regexPattern}$`);
    this.routes.push({ method: method.toUpperCase(), regex, paramNames, handler });
  }

  get(pattern, handler) { this.add('GET', pattern, handler); }
  post(pattern, handler) { this.add('POST', pattern, handler); }
  put(pattern, handler) { this.add('PUT', pattern, handler); }
  patch(pattern, handler) { this.add('PATCH', pattern, handler); }
  delete(pattern, handler) { this.add('DELETE', pattern, handler); }

  async handle(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Fleet-Key');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return true;
    }

    const host = req.headers.host || 'localhost';
    const parsedUrl = new URL(req.url, `http://${host}`);
    const pathname = parsedUrl.pathname;

    for (const route of this.routes) {
      if (route.method !== req.method) continue;
      const match = pathname.match(route.regex);
      if (match) {
        const params = {};
        route.paramNames.forEach((name, index) => {
          params[name] = decodeURIComponent(match[index + 1]);
        });
        req.params = params;
        req.query = Object.fromEntries(parsedUrl.searchParams.entries());

        if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
          try {
            req.body = await this.readJsonBody(req);
          } catch (err) {
            sendJson(res, err.statusCode || 400, {
              error: err.code || 'BAD_REQUEST',
              message: err.message
            });
            return true;
          }
        } else {
          req.body = {};
        }

        try {
          await route.handler(req, res);
        } catch (handlerErr) {
          console.error(`Unhandled error on ${req.method} ${pathname}:`, handlerErr);
          if (!res.headersSent) {
            sendJson(res, 500, {
              error: 'INTERNAL_SERVER_ERROR',
              message: handlerErr.message
            });
          }
        }
        return true;
      }
    }

    return false; // Not matched by router
  }

  readJsonBody(req) {
    return new Promise((resolve, reject) => {
      let totalSize = 0;
      const chunks = [];

      req.on('data', chunk => {
        totalSize += chunk.length;
        if (totalSize > this.maxBodyBytes) {
          const err = new Error('Payload Too Large');
          err.statusCode = 413;
          err.code = 'PAYLOAD_TOO_LARGE';
          req.destroy();
          reject(err);
          return;
        }
        chunks.push(chunk);
      });

      req.on('end', () => {
        if (chunks.length === 0) return resolve({});
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        if (!raw) return resolve({});
        try {
          const parsed = JSON.parse(raw);
          resolve(parsed);
        } catch (err) {
          const jsonErr = new Error('Request body must be valid JSON');
          jsonErr.statusCode = 400;
          jsonErr.code = 'MALFORMED_JSON';
          reject(jsonErr);
        }
      });

      req.on('error', err => reject(err));
    });
  }
}

export function sendJson(res, statusCode, data) {
  if (!res.headersSent) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  }
  res.end(JSON.stringify(data));
}

export default Router;
