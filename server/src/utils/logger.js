/**
 * LocalPilot Fleet — Structured Logger
 * server/src/utils/logger.js
 */

const LOG_LEVELS = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

const currentLevel = (process.env.LOG_LEVEL || 'info').toLowerCase();
const minLevelValue = LOG_LEVELS[currentLevel] || LOG_LEVELS.info;

function formatMessage(level, message, meta = null) {
  const timestamp = new Date().toISOString();
  const entry = {
    timestamp,
    level: level.toUpperCase(),
    message
  };
  if (meta && typeof meta === 'object') {
    Object.assign(entry, meta);
  }
  return entry;
}

export const logger = {
  debug(message, meta) {
    if (minLevelValue <= LOG_LEVELS.debug) {
      const entry = formatMessage('debug', message, meta);
      console.debug(`[${entry.timestamp}] [DEBUG] ${message}`, meta ? JSON.stringify(meta) : '');
    }
  },
  info(message, meta) {
    if (minLevelValue <= LOG_LEVELS.info) {
      const entry = formatMessage('info', message, meta);
      console.log(`[${entry.timestamp}] [INFO] ${message}`, meta ? JSON.stringify(meta) : '');
    }
  },
  warn(message, meta) {
    if (minLevelValue <= LOG_LEVELS.warn) {
      const entry = formatMessage('warn', message, meta);
      console.warn(`[${entry.timestamp}] [WARN] ${message}`, meta ? JSON.stringify(meta) : '');
    }
  },
  error(message, meta) {
    if (minLevelValue <= LOG_LEVELS.error) {
      const entry = formatMessage('error', message, meta);
      console.error(`[${entry.timestamp}] [ERROR] ${message}`, meta ? (meta instanceof Error ? meta.stack : JSON.stringify(meta)) : '');
    }
  }
};

export default logger;
