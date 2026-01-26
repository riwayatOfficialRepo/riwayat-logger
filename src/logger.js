const pino = require('pino');

const sensitiveKeys = new Set(['mobileNumber', 'phone', 'email', 'password', 'pin', 'token', 'cardNumber']);
const sensitiveHeaderKeys = new Set(['authorization', 'cookie']);

function maskSensitive(value, visible = 4) {
  if (!value) return '';
  const len = value.length;
  if (len <= visible) return '*'.repeat(len);
  return '*'.repeat(len - visible) + value.slice(-visible);
}

function maskObject(obj, seen = new WeakSet()) {
  if (!obj || typeof obj !== 'object') return obj;
  if (seen.has(obj)) return '[Circular]';
  seen.add(obj);

  if (Array.isArray(obj)) {
    return obj.map(item => maskObject(item, seen));
  }

  if (obj.constructor !== Object) return obj;

  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (sensitiveKeys.has(key)) {
      out[key] = (key === 'mobileNumber' || key === 'phone' || key === 'pin')
        ? maskSensitive(String(value))
        : '***';
    } else if (value && typeof value === 'object') {
      out[key] = maskObject(value, seen);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function maskHeaders(headers) {
  const out = { ...headers };
  for (const key of sensitiveHeaderKeys) {
    if (out[key]) out[key] = '*****';
  }
  return out;
}

const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'production'
    ? undefined
    : {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'yyyy-mm-dd HH:MM:ss', ignore: 'pid,hostname' },
      },
});

/**
 * Express logging middleware
 */
function loggingMiddleware(req, res, next) {
  const start = Date.now();

  logger.info({
    traceId: req.traceId,
    method: req.method,
    url: req.originalUrl,
    body: maskObject(req.body),
    query: maskObject(req.query),
    params: maskObject(req.params),
    headers: maskHeaders(req.headers),
    remoteAddress: req.ip,
  }, '📩 Incoming request');

  res.on('finish', () => {
    logger.info({
      traceId: req.traceId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration_ms: Date.now() - start,
    }, '📤 Response sent');
  });

  next();
}

/**
 * Logger wrapper that always masks sensitive data and adds traceId
 */
function withTrace(reqOrTraceId) {
  const traceId = typeof reqOrTraceId === 'string'
    ? reqOrTraceId
    : reqOrTraceId?.traceId;

  function normalize(obj, msg) {
    // If first argument is string → treat as message
    if (typeof obj === 'string') {
      return { data: {}, msg: obj };
    }

    // If only object passed
    if (obj && !msg) {
      return { data: obj, msg: undefined };
    }

    return { data: obj || {}, msg };
  }

  return {
    info: (obj, msg) => {
      const { data, msg: finalMsg } = normalize(obj, msg);
      logger.info({ traceId, ...maskObject(data) }, finalMsg);
    },

    warn: (obj, msg) => {
      const { data, msg: finalMsg } = normalize(obj, msg);
      logger.warn({ traceId, ...maskObject(data) }, finalMsg);
    },

    debug: (obj, msg) => {
      const { data, msg: finalMsg } = normalize(obj, msg);
      logger.debug({ traceId, ...maskObject(data) }, finalMsg);
    },

    error: (obj, msg) => {
      const { data, msg: finalMsg } = normalize(obj, msg);
      logger.error({ traceId, ...maskObject(data) }, finalMsg);
    },
  };
}


logger.maskObject = maskObject;
logger.maskSensitive = maskSensitive;
logger.maskHeaders = maskHeaders;
logger.loggingMiddleware = loggingMiddleware;
logger.withTrace = withTrace;

module.exports = logger;
