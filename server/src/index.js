/**
 * LocalPilot Fleet — Master Backend Service & Server Entrypoint
 * server/src/index.js
 *
 * REST API, Server-Sent Events, SQLite WAL engine, and Command Center Web Console.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { initDb, closeDb } from './db.js';
import { Router, sendJson } from './utils/router.js';
import { setFleetKey, getFleetKey } from './utils/auth.js';
import logger from './utils/logger.js';
import { registerEventRoutes, sseClients } from './routes/events.js';
import { registerNodeRoutes } from './routes/nodes.js';
import { registerFleetRoutes } from './routes/fleet.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// MIME dictionary for dashboard static files
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

// CLI Flag Parser
function parseCliArgs() {
  const args = process.argv.slice(2);
  const flags = {};
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        flags[key] = args[++i];
      } else {
        flags[key] = true;
      }
    }
  }
  return flags;
}

export function createServer(options = {}) {
  const flags = parseCliArgs();

  const port = Number(options.port ?? flags.port ?? process.env.PORT ?? 8443);
  const host = options.host ?? flags.host ?? process.env.HOST ?? '0.0.0.0';
  const fleetKey = options.fleetKey ?? flags['fleet-key'] ?? process.env.FLEET_KEY ?? 'localpilot-secret-key-2026';
  const dbPath = options.dbPath ?? flags.db ?? process.env.DB_PATH ?? path.join(__dirname, '../data/fleet.db');
  const dashboardDir = path.resolve(
    options.dashboardPath ?? flags.dashboard ?? process.env.DASHBOARD_PATH ?? path.join(__dirname, '../../dashboard')
  );

  setFleetKey(fleetKey);

  // Initialize DB if not provided
  let db = options.db;
  if (!db) {
    db = initDb(dbPath, { seed: options.seed !== false });
  }

  const router = new Router();

  // Health endpoint
  router.get('/api/v1/health', (req, res) => {
    sendJson(res, 200, {
      status: 'ok',
      service: 'LocalPilot Fleet Server',
      timestamp: new Date().toISOString(),
      uptime_seconds: Math.floor(process.uptime())
    });
  });

  // Register API routes
  registerEventRoutes(router);
  registerNodeRoutes(router);
  registerFleetRoutes(router);

  const server = http.createServer(async (req, res) => {
    try {
      // 1. Try API Router
      const handled = await router.handle(req, res);
      if (handled) return;

      // 2. Static Dashboard File Serving
      const hostHeader = req.headers.host || 'localhost';
      const parsedUrl = new URL(req.url, `http://${hostHeader}`);
      let reqPath = decodeURIComponent(parsedUrl.pathname);

      if (reqPath === '/' || reqPath === '') {
        reqPath = '/index.html';
      }

      // Security check: Path traversal prevention
      const safeSuffix = path.normalize(reqPath).replace(/^(\.\.[/\\])+/, '');
      let filePath = path.join(dashboardDir, safeSuffix);

      if (!filePath.startsWith(dashboardDir)) {
        sendJson(res, 403, { error: 'FORBIDDEN', message: 'Path traversal disallowed' });
        return;
      }

      // If directory, try index.html inside it
      if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
        filePath = path.join(filePath, 'index.html');
      }

      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': contentType });
        fs.createReadStream(filePath).pipe(res);
        return;
      }

      // SPA Fallback: If not an API route and index.html exists, serve index.html
      const fallbackIndex = path.join(dashboardDir, 'index.html');
      if (!reqPath.startsWith('/api/') && fs.existsSync(fallbackIndex)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        fs.createReadStream(fallbackIndex).pipe(res);
        return;
      }

      // Route / file not found
      sendJson(res, 404, {
        error: 'NOT_FOUND',
        message: `Endpoint or file '${parsedUrl.pathname}' not found`
      });
    } catch (err) {
      logger.error('Fatal request handling error', { error: err.message, stack: err.stack });
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'SERVER_ERROR', message: err.message });
      }
    }
  });

  server.port = port;
  server.host = host;
  return server;
}

// Top-level entrypoint execution when launched via node src/index.js
const isMain = process.argv[1] && (
  import.meta.url === pathToFileURL(process.argv[1]).href ||
  path.resolve(process.argv[1]) === path.resolve(__filename)
);

if (isMain) {
  const flags = parseCliArgs();
  const port = Number(flags.port ?? process.env.PORT ?? 8443);
  const host = flags.host ?? process.env.HOST ?? '0.0.0.0';

  const server = createServer();

  server.listen(port, host, () => {
    logger.info(`LocalPilot Fleet Server listening on http://${host}:${port}`);
    logger.info(`REST API available at http://${host}:${port}/api/v1/`);
    logger.info(`Health check: http://${host}:${port}/api/v1/health`);
  });

  // Graceful shutdown
  const shutdown = () => {
    logger.info('Shutting down LocalPilot Fleet Server gracefully...');

    // Notify SSE clients
    for (const client of sseClients) {
      try {
        client.write('event: shutdown\ndata: {"message":"Server is shutting down"}\n\n');
        client.end();
      } catch {}
    }
    sseClients.clear();

    server.close(() => {
      logger.info('HTTP server closed.');
      closeDb();
      logger.info('Database connection closed. Goodbye.');
      process.exit(0);
    });

    setTimeout(() => {
      logger.warn('Force exiting after shutdown timeout.');
      process.exit(1);
    }, 5000).unref();
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

export default createServer;
