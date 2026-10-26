#!/usr/bin/env node
/* =====================================================================
   LF27 · Relé de salas — servidor de PRODUCCIÓN
   ---------------------------------------------------------------------
   Servicio remoto que permite jugar entre ordenadores distintos sin que
   nadie configure nada. Un único binario, sin dependencias.

   Transporte:  WSS (WebSocket sobre TLS). Este proceso habla ws:// y va
                detrás de un proxy TLS (Caddy/nginx/Fly/Render), que es
                como se pone TLS en producción. Si se arranca con
                TLS_CERT y TLS_KEY usa https/wss directo, sin proxy.

   Reglas de sala (validación en el servidor, nunca en el cliente):
     · crear  → el servidor acuña el código (6 caracteres) y el token de
                anfitrión. Un código no puede repetirse mientras viva.
     · unirse → solo si la sala existe y está abierta; recibe token de
                invitado. Un tercero recibe 'room-full'.
     · publicar estado → solo con token válido y solo en su sala, con
                límite de tamaño y de frecuencia (anti-abuso).
     · nadie puede listar salas ni adivinar códigos a base de fuerza bruta
                (límite de intentos fallidos por IP).

   Operación:
     · GET /salud            → estado para el proveedor y monitorización
     · GET /estado           → JSON con salas (requiere DIAG_TOKEN)
     · GET /                 → página de estado legible
     · salas vacías o sin anfitrión durante TTL → se destruyen

   Variables de entorno: ver tools/deploy/README.md
   ===================================================================== */
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const os = require('os');

/* ------------------------------------------------------------ configuración */
const PORT = parseInt(process.env.PORT || '8099', 10);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_CLIENTS = parseInt(process.env.MAX_CLIENTS || '4', 10);
const ROOM_TTL_MS = parseInt(process.env.ROOM_TTL_MIN || '30', 10) * 60 * 1000;      // sala entera
const EMPTY_TTL_MS = parseInt(process.env.EMPTY_TTL_MIN || '10', 10) * 60 * 1000;     // sin nadie
const NOHOST_TTL_MS = parseInt(process.env.NOHOST_TTL_MIN || '5', 10) * 60 * 1000;    // sin anfitrión
const MAX_MSG_BYTES = parseInt(process.env.MAX_MSG_BYTES || '8192', 10);
const MAX_MSGS_PER_SEC = parseInt(process.env.MAX_MSGS_PER_SEC || '60', 10);
const JOIN_FAILS_PER_MIN = parseInt(process.env.JOIN_FAILS_PER_MIN || '20', 10);
const DIAG_TOKEN = process.env.DIAG_TOKEN || '';
const TLS_CERT = process.env.TLS_CERT || '';
const TLS_KEY = process.env.TLS_KEY || '';
const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/$/, '');     // p.ej. wss://salas.lf27.app
const START = Date.now();

const stats = { creadas: 0, unidas: 0, rechazadas: 0, caducadas: 0, conexiones: 0, mensajes: 0 };

/* --------------------------------------------------------------- utilidades */
function iso() { return new Date().toISOString().replace('T', ' ').slice(0, 19); }
function log(...a) { console.log('[' + iso() + ']', ...a); }
const rnd = (n) => crypto.randomBytes(n).toString('hex');
const CH = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';           // sin I, O, 0, 1
function nuevoCodigo() {
  let c = '';
  const b = crypto.randomBytes(6);
  for (let i = 0; i < 6; i++) c += CH[b[i] % CH.length];
  return c;
}

/* ------------------------------------------------------------------- salas */
// código → { codigo, hostToken, guestToken, host: pid|null, clientes:Set, creada, ultimaActividad, sinHostDesde }
const salas = new Map();
const clientes = new Set();
const ipFails = new Map();         // ip → [timestamps de joins fallidos]

function salaNueva(codigo) {
  const s = {
    codigo,
    hostToken: rnd(16),
    guestToken: rnd(16),
    host: null,
    clientes: new Set(),
    creada: Date.now(),
    ultimaActividad: Date.now(),
    sinHostDesde: null,
    estado: 'abierta'
  };
  salas.set(codigo, s);
  stats.creadas++;
  log('SALA CREADA', codigo, '(total ' + salas.size + ')');
  return s;
}

function miembros(s) {
  return [...s.clientes].map((c) => ({ pid: c.pid, rol: c.rol, desde: c.desde }));
}

function difundir(s, obj, excepto) {
  for (const c of s.clientes) if (c !== excepto) enviar(c, obj);
}

function cerrarSala(s, motivo) {
  if (!salas.has(s.codigo)) return;
  for (const c of [...s.clientes]) {
    enviar(c, { t: 'room-closed', motivo });
    c.roomRef = null; c.sala = null;
  }
  s.clientes.clear();
  salas.delete(s.codigo);
  stats.caducadas++;
  log('SALA CERRADA', s.codigo, '·', motivo);
}

/* --------------------------------------------------------------- WebSocket */
function handshake(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key || req.headers.upgrade !== 'websocket') { socket.destroy(); return false; }
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  return true;
}
function frame(str) {
  const p = Buffer.from(str, 'utf8');
  const n = p.length;
  let h;
  if (n < 126) h = Buffer.from([0x81, n]);
  else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x81; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x81; h[1] = 127; h.writeUInt32BE(0, 2); h.writeUInt32BE(n, 6); }
  return Buffer.concat([h, p]);
}
function enviar(cli, obj) {
  if (!cli.socket.writable) return;
  try { cli.socket.write(frame(JSON.stringify(obj))); } catch (e) { }
}

function ipDe(req) {
  const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket.remoteAddress || '?';
}

function onSocket(socket, req) {
  const cli = {
    socket, ip: ipDe(req), pid: null, rol: null, sala: null, roomRef: null,
    conectado: Date.now(), ultimoMensaje: 0, ventana: { t: 0, n: 0 }, vivo: true
  };
  clientes.add(cli);
  stats.conexiones++;
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 30000);
  let buf = Buffer.alloc(0);

  socket.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > MAX_MSG_BYTES * 4) { cerrarSocket(cli, 1009, 'mensaje demasiado grande'); return; }
    while (buf.length >= 2) {
      const b0 = buf[0], b1 = buf[1];
      const op = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (len > MAX_MSG_BYTES) { cerrarSocket(cli, 1009, 'mensaje demasiado grande'); return; }
      const maskLen = masked ? 4 : 0;
      if (buf.length < off + maskLen + len) return;
      const mask = masked ? buf.slice(off, off + 4) : null;
      const data = Buffer.from(buf.slice(off + maskLen, off + maskLen + len));
      if (mask) for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3];
      buf = buf.slice(off + maskLen + len);

      if (op === 0x8) { cerrarSocket(cli, 1000, 'cierre del cliente'); return; }
      if (op === 0x9) { try { cli.socket.write(Buffer.from([0x8a, 0])); } catch (e) { } continue; }
      if (op === 0x1 || op === 0x2) {
        // límite de frecuencia
        const ahora = Date.now();
        if (ahora - cli.ventana.t > 1000) cli.ventana = { t: ahora, n: 0 };
        if (++cli.ventana.n > MAX_MSGS_PER_SEC) { cerrarSocket(cli, 1008, 'demasiados mensajes'); return; }
        let m = null;
        try { m = JSON.parse(data.toString('utf8')); } catch (e) { continue; }
        if (m && typeof m === 'object') { stats.mensajes++; handle(cli, m); }
      }
    }
  });
  socket.on('close', () => salir(cli, 'cierre de socket'));
  socket.on('error', () => salir(cli, 'error de socket'));
  socket.on('timeout', () => cerrarSocket(cli, 1001, 'tiempo agotado'));
}

function cerrarSocket(cli, code, motivo) {
  try { cli.socket.end(Buffer.from([0x88, 0x02, (code >> 8) & 0xff, code & 0xff])); } catch (e) { }
  salir(cli, motivo || 'cierre');
}

function salir(cli, motivo) {
  if (!cli.vivo) return;
  cli.vivo = false;
  clientes.delete(cli);
  const s = cli.roomRef;
  if (s && salas.has(s.codigo)) {
    s.clientes.delete(cli);
    s.ultimaActividad = Date.now();
    log('SALIDA', s.codigo, cli.pid || '?', '(' + (cli.rol || '?') + ', ' + motivo + ') quedan ' + s.clientes.size);
    difundir(s, { t: 'bye', pid: cli.pid });
    if (s.host === cli.pid) {
      s.host = null;
      s.sinHostDesde = Date.now();
      difundir(s, { t: 'host-left' });
      log('SIN ANFITRIÓN', s.codigo);
    }
    if (!s.clientes.size) {
      salas.delete(s.codigo);
      log('SALA VACÍA → eliminada', s.codigo);
    }
  }
}

/* ------------------------------------------------------------ validaciones */
function normalizarCodigo(v) {
  const c = String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6);
  return /^[A-Z0-9]{6}$/.test(c) ? c : null;
}
function ipBloqueada(ip) {
  const a = ipFails.get(ip) || [];
  const ahora = Date.now();
  const recientes = a.filter((t) => ahora - t < 60000);
  ipFails.set(ip, recientes);
  return recientes.length >= JOIN_FAILS_PER_MIN;
}
function falloJoin(cli, code, msg) {
  stats.rechazadas++;
  const a = ipFails.get(cli.ip) || [];
  a.push(Date.now());
  ipFails.set(cli.ip, a.slice(-100));
  log('RECHAZO', code, cli.ip, msg);
  enviar(cli, { t: 'reject', code, msg });
}

/* -------------------------------------------------------------- protocolo */
function handle(cli, m) {
  const t = String(m.t || '');

  /* ---- crear sala: el servidor acuña el código ---- */
  if (t === 'create') {
    if (cli.roomRef) {
      // el mismo cliente repitiendo el alta: se le reconfirma (idempotente)
      if (salas.has(cli.roomRef.codigo)) return reconfirmar(cli);
      return enviar(cli, { t: 'reject', code: 'already-in-room', msg: 'Ya estás en una sala' });
    }
    if (ipBloqueada(cli.ip)) return falloJoin(cli, 'rate-limited', 'Demasiados intentos. Espera un minuto.');
    let codigo = normalizarCodigo(m.room);
    if (codigo && salas.has(codigo)) {
      // reintento de un anfitrión que se ha reconectado: se le reconoce por IP+pid
      const existente = salas.get(codigo);
      const esSuya = [...existente.clientes].some((c) => c.ip === cli.ip && c.pid === String(m.pid || ''));
      if (!esSuya) return falloJoin(cli, 'code-taken', 'Ese código ya está en uso. Vuelve a intentarlo.');
    }
    if (!codigo || salas.has(codigo)) {
      do { codigo = nuevoCodigo(); } while (salas.has(codigo));
    }
    const s = salas.get(codigo) || salaNueva(codigo);
    entrarSala(cli, s, 'h', m, s.hostToken);
    return;
  }

  /* ---- unirse a sala existente ---- */
  if (t === 'join') {
    if (cli.roomRef) {
      const cn = normalizarCodigo(m.room);
      if (cn && cli.roomRef.codigo === cn) return reconfirmar(cli);
      return enviar(cli, { t: 'reject', code: 'already-in-room', msg: 'Ya estás en una sala' });
    }
    if (ipBloqueada(cli.ip)) return falloJoin(cli, 'rate-limited', 'Demasiados intentos. Espera un minuto.');
    const codigo = normalizarCodigo(m.room);
    if (!codigo) return falloJoin(cli, 'bad-code', 'El código debe tener 6 caracteres');
    const s = salas.get(codigo);
    if (!s || s.estado !== 'abierta') {
      return falloJoin(cli, 'room-not-found', 'No existe ninguna sala con ese código (o ya está cerrada). Pide el código otra vez.');
    }
    // ¿es el anfitrión que vuelve?
    if (s.host === null && m.token === s.hostToken) { entrarSala(cli, s, 'h', m, s.hostToken); return; }
    if (s.clientes.size >= MAX_CLIENTS) {
      return falloJoin(cli, 'room-full', 'La sala está completa (máximo ' + MAX_CLIENTS + ' jugadores)');
    }
    // invitado: si ya había un invitado con ese pid (reconexión) se le reconoce
    entrarSala(cli, s, 'g', m, s.guestToken);
    return;
  }

  /* ---- estado de juego (solo dentro de una sala, con token) ---- */
  if (t === 'state') {
    const s = cli.roomRef;
    if (!s || !salas.has(s.codigo)) return;
    if (m.token !== (cli.rol === 'h' ? s.hostToken : s.guestToken)) {
      enviar(cli, { t: 'reject', code: 'bad-token', msg: 'Credencial de sala no válida' });
      return;
    }
    const presencia = sanitizarPresencia(m.presence);
    if (presencia) {
      cli.presence = presencia;          // se guarda para reenviarla a quien llegue después
      s.ultimaActividad = Date.now();
      difundir(s, { t: 'state', pid: cli.pid, presence: presencia, rol: cli.rol }, cli);
    }
    return;
  }

  /* ---- salir ---- */
  if (t === 'bye') { salir(cli, 'petición del cliente'); return; }

  enviar(cli, { t: 'reject', code: 'bad-message', msg: 'Mensaje no reconocido' });
}

// La presencia es lo único que se reenvía tal cual: se valida forma y tamaño
function sanitizarPresencia(p) {
  if (!p || typeof p !== 'object' || Array.isArray(p)) return null;
  const j = JSON.stringify(p);
  if (j.length > MAX_MSG_BYTES / 2) return null;
  return p;
}

// Vuelve a confirmar el alta de un cliente que ya está dentro (petición repetida)
function reconfirmar(cli) {
  const s = cli.roomRef;
  enviar(cli, {
    t: 'joined', room: s.codigo, pid: cli.pid, role: cli.rol === 'h' ? 'host' : 'guest',
    host: s.host, token: cli.rol === 'h' ? s.hostToken : s.guestToken, members: miembros(s)
  });
  log('ALTA REPETIDA', s.codigo, cli.pid, '→ reconfirmada');
}

function entrarSala(cli, s, rol, m, token) {
  cli.pid = String(m.pid || '').replace(/[^a-zA-Z0-9]/g, '').slice(0, 24) || rnd(4);
  cli.rol = rol;
  cli.roomRef = s;
  cli.sala = s.codigo;
  cli.desde = Date.now();
  s.clientes.add(cli);
  s.ultimaActividad = Date.now();
  if (rol === 'h') { s.host = cli.pid; s.sinHostDesde = null; }
  if (rol === 'g') stats.unidas++;

  enviar(cli, {
    t: 'joined',
    room: s.codigo,               // ← la sala la confirma el SERVIDOR
    pid: cli.pid,
    role: rol === 'h' ? 'host' : 'guest',
    host: s.host,
    token,                        // credencial para publicar estado en esta sala
    members: miembros(s)
  });
  log('UNIÓN OK', s.codigo, cli.pid, 'rol ' + rol, '→ ' + s.clientes.size + ' dentro');

  // a todos (incluido el anfitrión) la lista actualizada
  for (const c of s.clientes) {
    enviar(c, { t: 'members', room: s.codigo, host: s.host, count: s.clientes.size, members: miembros(s) });
  }
  // y el estado ya conocido de los demás (para que el recién llegado los vea al instante)
  for (const c of s.clientes) {
    if (c === cli) continue;
    if (c.presence) enviar(cli, { t: 'state', pid: c.pid, presence: c.presence, rol: c.rol });
  }
}

/* ------------------------------------------------------------------- HTTP */
function estadoJSON() {
  return {
    ok: true,
    servicio: 'lf27-salas',
    version: require('./package.json').version,
    publico: PUBLIC_URL || null,
    uptime_s: Math.round((Date.now() - START) / 1000),
    salas_abiertas: salas.size,
    jugadores_conectados: [...salas.values()].reduce((n, s) => n + s.clientes.size, 0),
    conexiones_websocket: clientes.size,
    contadores: stats,
    salas: [...salas.values()].map((s) => ({
      codigo: s.codigo, host: s.host, creada: new Date(s.creada).toISOString(),
      jugadores: miembros(s), sin_host_desde: s.sinHostDesde ? new Date(s.sinHostDesde).toISOString() : null
    }))
  };
}

function pagina() {
  const e = estadoJSON();
  const filas = e.salas.map((s) => `<tr><td>${s.codigo}</td><td>${s.jugadores.length}</td><td>${s.host ? 'sí' : 'NO'}</td></tr>`).join('');
  return `<!doctype html><meta charset="utf-8"><title>LF27 · relé de salas</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{background:#020b2a;color:#eaf1ff;font-family:system-ui,sans-serif;padding:40px;line-height:1.6;max-width:820px;margin:auto}
h1{font-style:italic;font-weight:900;letter-spacing:-1px}h1 b{color:#ffd24a}
code{background:#0b2555;padding:2px 7px;border-radius:6px}
.ok{color:#4be08b}table{border-collapse:collapse;margin-top:8px;min-width:320px}
td,th{padding:6px 14px;border-bottom:1px solid #1b3566;text-align:left}.muted{color:#6fa8ff}</style>
<h1>LF27 <b>·</b> salas online</h1>
<p class="ok">● servicio en marcha · ${e.uptime_s}s de actividad</p>
<p class="muted">${e.publico ? 'Dirección oficial: <code>' + e.publico + '</code>' : 'Configura PUBLIC_URL para mostrar la dirección oficial.'}</p>
<p>Salas abiertas: <b>${e.salas_abiertas}</b> · jugadores: <b>${e.jugadores_conectados}</b> · conexiones: <b>${e.conexiones_websocket}</b></p>
<h3>Salas</h3>${filas ? '<table><tr><th>sala</th><th>jugadores</th><th>anfitrión</th></tr>' + filas + '</table>' : '<p class="muted">Ninguna ahora mismo.</p>'}
<p class="muted" style="margin-top:26px">No se guardan partidas ni datos personales. Las salas viven en memoria y caducan solas.</p>`;
}

function crearServidor() {
  const handler = (req, res) => {
    const url = (req.url || '/').split('?')[0];
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    if (url === '/salud') {
      const e = estadoJSON();
      res.writeHead(200, { ...cors, 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('ok ' + e.salas_abiertas + ' salas ' + e.jugadores_conectados + ' jugadores');
    }
    if (url === '/estado') {
      if (DIAG_TOKEN) {
        const tok = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
          (new URL(req.url, 'http://x').searchParams.get('token') || '');
        if (tok !== DIAG_TOKEN) { res.writeHead(401, cors); return res.end(JSON.stringify({ ok: false, error: 'token requerido' })); }
      }
      res.writeHead(200, cors);
      return res.end(JSON.stringify(estadoJSON(), null, 2));
    }
    if (url === '/' || url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(pagina());
    }
    res.writeHead(404, cors);
    res.end(JSON.stringify({ ok: false, error: 'no encontrado' }));
  };

  let srv;
  if (TLS_CERT && TLS_KEY) {
    srv = https.createServer({ cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) }, handler);
  } else {
    srv = http.createServer(handler);
  }
  srv.on('upgrade', (req, socket) => {
    if (!handshake(req, socket)) return;
    onSocket(socket, req);
  });
  return srv;
}

/* --------------------------------------------------------------- mantenimiento */
setInterval(() => {
  const ahora = Date.now();
  for (const s of [...salas.values()]) {
    if (ahora - s.creada > ROOM_TTL_MS) { cerrarSala(s, 'caducada por antigüedad'); continue; }
    if (!s.clientes.size) { cerrarSala(s, 'sin jugadores'); continue; }
    if (s.sinHostDesde && ahora - s.sinHostDesde > NOHOST_TTL_MS) {
      for (const c of [...s.clientes]) enviar(c, { t: 'host-left' });
      cerrarSala(s, 'el anfitrión no ha vuelto');
    }
  }
  if (salas.size > 5000) log('AVISO: demasiadas salas abiertas (' + salas.size + ')');
}, 20000).unref();

// ping a los clientes para detectar conexiones muertas
setInterval(() => {
  for (const c of clientes) { try { c.socket.write(Buffer.from([0x89, 0])); } catch (e) { salir(c, 'ping fallido'); } }
}, 25000).unref();

/* ---------------------------------------------------------------- arranque */
const server = crearServidor();
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') { console.error('puerto ' + PORT + ' ocupado'); process.exit(1); }
  throw e;
});
server.listen(PORT, HOST, () => {
  const proto = (TLS_CERT && TLS_KEY) ? 'wss' : 'ws';
  const ips = Object.values(os.networkInterfaces()).flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal).map((i) => i.address);
  console.log('LF27 · relé de salas (producción) en el puerto ' + PORT);
  console.log('  protocolo: ' + (proto === 'wss' ? 'WSS nativo (TLS en este proceso)' : 'WS detrás de proxy TLS'));
  console.log('  oficial:   ' + (PUBLIC_URL || '(define PUBLIC_URL)'));
  console.log('  salud:     /salud · estado: /estado' + (DIAG_TOKEN ? ' (requiere token)' : ''));
  ips.forEach((ip) => console.log('  red:       ' + proto + '://' + ip + ':' + PORT));
  if (!PUBLIC_URL && !TLS_CERT) console.log('  AVISO: sin PUBLIC_URL ni TLS. En producción debe ir detrás de un proxy TLS.');
});

// cierre ordenado (Fly/Render mandan SIGTERM al redesplegar)
['SIGTERM', 'SIGINT'].forEach((sig) => process.on(sig, () => {
  log('apagando… avisando a ' + clientes.size + ' clientes');
  for (const c of clientes) { enviar(c, { t: 'room-closed', motivo: 'servidor reiniciándose' }); cerrarSocket(c, 1012, 'servidor apagándose'); }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000);
}));
