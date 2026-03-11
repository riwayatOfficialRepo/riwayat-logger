const pino = require('pino');
const { AsyncLocalStorage } = require('async_hooks');

const store = new AsyncLocalStorage();

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

function getCtx() {
  const ctx = store.getStore();
  if (!ctx) return {};
  return { traceId: ctx.traceId };
}

const base = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'production'
    ? undefined
    : {
        target: 'pino-pretty',
        options: { colorize: true, translateTime: 'yyyy-mm-dd HH:MM:ss', ignore: 'pid,hostname' },
      },
});

function loggingMiddleware(req, res, next) {
  const start = Date.now();

  base.info({
    ...getCtx(),
    method: req.method,
    url: req.originalUrl,
    body: maskObject(req.body),
    query: maskObject(req.query),
    params: maskObject(req.params),
    headers: maskHeaders(req.headers),
    remoteAddress: req.ip,
  }, '📩 Incoming request');

  res.on('finish', () => {
    base.info({
      ...getCtx(),
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration_ms: Date.now() - start,
    }, '📤 Response sent');
  });

  next();
}

function withTrace(reqOrTraceId) {
  const traceId = typeof reqOrTraceId === 'string'
    ? reqOrTraceId
    : reqOrTraceId?.traceId;

  function normalize(obj, msg) {
    if (typeof obj === 'string') return { data: {}, msg: obj };
    if (obj && !msg) return { data: obj, msg: undefined };
    return { data: obj || {}, msg };
  }

  return {
    info:  (obj, msg) => { const { data, msg: m } = normalize(obj, msg); base.info( { traceId, ...maskObject(data) }, m); },
    warn:  (obj, msg) => { const { data, msg: m } = normalize(obj, msg); base.warn( { traceId, ...maskObject(data) }, m); },
    debug: (obj, msg) => { const { data, msg: m } = normalize(obj, msg); base.debug({ traceId, ...maskObject(data) }, m); },
    error: (obj, msg) => { const { data, msg: m } = normalize(obj, msg); base.error({ traceId, ...maskObject(data) }, m); },
  };
}

function log(method, data, msg) {
  if (typeof data === 'string') return base[method]({ ...getCtx() }, data);
  base[method]({ ...getCtx(), ...maskObject(data) }, msg);
}

const logger = {
  info:  (data, msg) => log('info',  data, msg),
  warn:  (data, msg) => log('warn',  data, msg),
  error: (data, msg) => log('error', data, msg),
  debug: (data, msg) => log('debug', data, msg),
  
  child: (bindings) => base.child(bindings),  // ← add this line

  withTrace,
  loggingMiddleware,
  maskObject,
  maskSensitive,
  maskHeaders,
  store,
};

module.exports = logger;
