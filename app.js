/* ============================================================
   UATPark · Sistema de estacionamiento universitario (prototipo web)
   Todo corre en memoria + localStorage. No hay backend real.
   ============================================================ */

const LS_KEY = 'uatParkingState_v1';
const RESERVA_MINUTOS = 20;

/* ================================================================
   SEGURIDAD Y VALIDACIONES
   Aviso honesto: en este prototipo todo corre en el navegador, así que estas
   medidas dificultan los errores y los engaños comunes, pero la protección
   real (verificar el correo, guardar contraseñas y archivos) necesita un servidor.
   ================================================================ */
const MODO_DEMO = true;                       // en la versión real: false (oculta la caja de demostración)
const DOMINIO_ALUMNOS  = 'alumnos.uat.edu.mx';
const DOMINIO_DOCENTES = 'docentes.uat.edu.mx';
const CLAVE_DEMO = 'Demo2026!';               // contraseña de las cuentas de ejemplo
const CLAVE_ADMIN_INICIAL = 'Admin2026!';     // contraseña inicial del administrador (cámbiala en la versión real)
const MAX_INTENTOS_LOGIN = 5;
const BLOQUEO_LOGIN_MS = 60 * 1000;
const HASH_RONDAS = 3000;
const LOGIN_KEY = 'uatParkingLogin_v1';

/* ---- SHA-256 sincrónico (funciona igual con file:// y con https) ---- */
const _SHA = (() => {
  const primos = [];
  for(let n = 2; primos.length < 64; n++){ if(primos.every(p => n % p)) primos.push(n); }
  const frac = x => ((x - Math.floor(x)) * 4294967296) >>> 0;
  return { K: primos.map(p => frac(Math.cbrt(p))), H0: primos.slice(0, 8).map(p => frac(Math.sqrt(p))) };
})();

function sha256Hex(texto){
  const datos = new TextEncoder().encode(texto);
  const len = datos.length;
  const total = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(total);
  buf.set(datos);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor((len * 8) / 4294967296));
  dv.setUint32(total - 4, (len * 8) >>> 0);
  const H = _SHA.H0.slice(), K = _SHA.K, w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for(let off = 0; off < total; off += 64){
    for(let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for(let i = 16; i < 64; i++){
      const s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
      const s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for(let i = 0; i < 64; i++){
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  return H.map(x => x.toString(16).padStart(8, '0')).join('');
}

function nuevaSal(){
  const b = new Uint8Array(16);
  (self.crypto || window.crypto).getRandomValues(b);
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}
function hashPassword(clave, sal){
  let h = sha256Hex(sal + ':' + clave);
  for(let i = 0; i < HASH_RONDAS; i++) h = sha256Hex(h + sal + clave);
  return h;
}
function credenciales(clave){
  const sal = nuevaSal();
  return { sal, hash: hashPassword(clave, sal) };
}

/* ---- Cuentas de demostración de versiones anteriores: se actualizan solas ---- */
const EMAILS_DEMO = {
  '20240001': '20240001@alumnos.uat.edu.mx',
  '20240002': '20240002@alumnos.uat.edu.mx',
  '20240003': '20240003@alumnos.uat.edu.mx',
  '20240004': '20240004@alumnos.uat.edu.mx',
  'E-1001':   'roberto.salinas@docentes.uat.edu.mx',
};
function migrarCuentasDemo(st){
  (st.users || []).forEach(u => {
    const nuevo = EMAILS_DEMO[u.id];
    if(nuevo && /@uat\.edu\.mx$/i.test(u.correo)){
      u.correo = nuevo;
      (st.rides || []).forEach(r => { if(r.userId === u.id) r.correo = nuevo; });
    }
    if((nuevo || u.id === 'admin') && !u.hash){
      Object.assign(u, credenciales(u.id === 'admin' ? CLAVE_ADMIN_INICIAL : CLAVE_DEMO));
    }
  });
}

/* ---- Validaciones de formularios (devuelven un texto de error o '' si está bien) ---- */
const LETRAS = 'A-Za-zÁÉÍÓÚÜÑáéíóúüñ';

function validarNombrePersona(n){
  if(n.length < 5) return 'Escribe tu nombre completo (nombre y apellidos).';
  if(n.length > 80) return 'El nombre es demasiado largo (máximo 80 caracteres).';
  if(!new RegExp(`^[${LETRAS}][${LETRAS}'’. -]*$`).test(n)) return 'El nombre solo puede llevar letras, espacios, punto, apóstrofo o guion.';
  const partes = n.split(' ').filter(Boolean);
  const soloLetras = p => p.replace(new RegExp(`[^${LETRAS}]`, 'g'), '');
  if(partes.length < 2 || partes.some(p => soloLetras(p).length < 2)) return 'Escribe nombre y apellido completos (cada parte con al menos 2 letras).';
  if(/(.)\1{3,}/.test(n.toLowerCase())) return 'El nombre no parece válido (letras repetidas).';
  return '';
}

function validarIdentificador(rol, id){
  if(/^admin/i.test(id)) return 'Ese identificador está reservado.';
  if(rol === 'estudiante'){
    return /^[A-Za-z0-9]{5,15}$/.test(id) ? '' : 'La matrícula debe tener de 5 a 15 letras o números, sin espacios ni símbolos.';
  }
  return /^[A-Za-z0-9-]{3,15}$/.test(id) ? '' : 'El número de empleado debe tener de 3 a 15 caracteres (letras, números o guion).';
}

function correoAlumnoEsperado(matricula){ return `${matricula.toLowerCase()}@${DOMINIO_ALUMNOS}`; }

function validarCorreoInstitucional(rol, correo, identificador){
  const c = correo.trim().toLowerCase();
  if(rol === 'estudiante'){
    const esperado = correoAlumnoEsperado(identificador);
    return c === esperado ? '' : `El correo de un alumno debe ser exactamente ${esperado} (tu matrícula seguida de @${DOMINIO_ALUMNOS}).`;
  }
  const re = new RegExp('^[a-z0-9]+([._-][a-z0-9]+)*@' + DOMINIO_DOCENTES.replace(/\./g, '\\.') + '$');
  return re.test(c) ? '' : `El correo de un docente debe terminar en @${DOMINIO_DOCENTES} (por ejemplo nombre.apellido@${DOMINIO_DOCENTES}).`;
}

const CLAVES_COMUNES = ['12345678','123456789','1234567890','password','password1','contrasena','contrasena1','qwerty123','abc12345','11111111','uatpark123','uat12345','admin123'];
function validarContrasena(clave, identificador, correo){
  const errores = [];
  if(clave.length < 8) errores.push('La contraseña debe tener al menos 8 caracteres.');
  if(clave.length > 64) errores.push('La contraseña es demasiado larga (máximo 64 caracteres).');
  if(!/[A-Za-z]/.test(clave) || !/\d/.test(clave)) errores.push('La contraseña debe incluir letras y números.');
  const baja = clave.toLowerCase();
  if(baja === String(identificador).toLowerCase() || baja === correo.split('@')[0].toLowerCase()) errores.push('La contraseña no puede ser igual a tu matrícula o a tu correo.');
  if(CLAVES_COMUNES.includes(baja)) errores.push('Esa contraseña es muy común; elige otra.');
  return errores;
}

function normalizarPlaca(p){ return p.toUpperCase().trim().replace(/\s+/g, '-'); }
function clavePlaca(p){ return p.toUpperCase().replace(/[^A-Z0-9]/g, ''); }
function validarPlaca(p){
  const limpia = clavePlaca(p);
  if(!/^[A-Za-z0-9\s-]+$/.test(p) || !/^[A-Z0-9]{5,8}$/.test(limpia) || !/[A-Z]/.test(limpia) || !/\d/.test(limpia)){
    return 'La placa debe tener de 5 a 8 letras y números (ej. TAM-1234 o ABC-12-34).';
  }
  return '';
}
function validarLicencia(l){
  return /^[A-Za-z0-9-]{6,20}$/.test(l) ? '' : 'El número de licencia debe tener de 6 a 20 letras, números o guiones.';
}
function validarArchivo(file){
  if(!file) return 'Adjunta tu documento (PDF, JPG o PNG).';
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  if(!['application/pdf','image/jpeg','image/png'].includes(file.type) || !['pdf','jpg','jpeg','png'].includes(ext)){
    return 'El documento debe ser PDF, JPG o PNG.';
  }
  if(file.size > 5 * 1024 * 1024) return 'El documento no puede pesar más de 5 MB.';
  if(file.size < 1024) return 'El archivo parece vacío o dañado.';
  return '';
}

/* ---- Bloqueo por intentos fallidos de inicio de sesión ---- */
function leerIntentosLogin(){
  try{ return JSON.parse(localStorage.getItem(LOGIN_KEY)) || { n:0, hasta:0 }; }catch(e){ return { n:0, hasta:0 }; }
}
function loginBloqueadoMs(){ return Math.max(0, (leerIntentosLogin().hasta || 0) - Date.now()); }
function registrarFalloLogin(){
  const t = leerIntentosLogin();
  t.n = (t.n || 0) + 1;
  let restantes = MAX_INTENTOS_LOGIN - t.n;
  if(t.n >= MAX_INTENTOS_LOGIN){ t.hasta = Date.now() + BLOQUEO_LOGIN_MS; t.n = 0; restantes = 0; }
  localStorage.setItem(LOGIN_KEY, JSON.stringify(t));
  return restantes;
}
function limpiarFallosLogin(){ localStorage.removeItem(LOGIN_KEY); }

/* ---- Estado de la cuenta (validación por la administración) ---- */
function cuentaActiva(u){
  u = u || currentUser();
  return !!u && (u.rol === 'administrador' || !u.estadoCuenta || u.estadoCuenta === 'validada');
}
function mensajeCuenta(u){
  if(!u) return '';
  if(u.estadoCuenta === 'pendiente') return 'Tu cuenta está pendiente de validación. La administración revisa tu documento y, al aprobarla, podrás reservar, pedir aventón y enviar reportes. Mientras tanto puedes explorar el mapa.';
  if(u.estadoCuenta === 'rechazada') return 'Tu cuenta no pudo validarse. Acude con la administración del estacionamiento para aclarar tu documento.';
  return '';
}
function exigirCuentaActiva(){
  const u = currentUser();
  if(cuentaActiva(u)) return true;
  openModal('Cuenta no validada', `<p class="small">${esc(mensajeCuenta(u))}</p>`, [['Entendido', closeModal, 'btn-primary']]);
  return false;
}

/* ---- Antiabuso: 3 reservaciones vencidas en 24 h bloquean nuevas reservas por 24 h ---- */
function bloqueoNoShowMs(userId){
  const DIA = 24 * 3600 * 1000;
  const vencidas = state.reservations
    .filter(r => r.userId === userId && r.status === 'expirada' && Date.now() - r.expiresAt < DIA)
    .sort((a, b) => b.expiresAt - a.expiresAt);
  if(vencidas.length < 3) return 0;
  return Math.max(0, vencidas[0].expiresAt + DIA - Date.now());
}
function fmtDuracion(ms){
  const m = Math.ceil(ms / 60000), h = Math.floor(m / 60);
  return h ? `${h} h ${m % 60} min` : `${m} min`;
}

function mostrarErrores(id, lista){
  const box = document.getElementById(id);
  if(!box) return;
  const items = (lista || []).filter(Boolean);
  if(!items.length){ box.hidden = true; box.innerHTML = ''; return; }
  box.hidden = false;
  box.innerHTML = '<ul>' + items.map(m => `<li>${esc(m)}</li>`).join('') + '</ul>';
}

/* ---------------- Coordenadas del mapa (idénticas al plano entregado) ---------------- */
const LANES = [
  { left:125, top:25, width:40, height:497, arrow:'down' },
  { left:255, top:25, width:40, height:497, arrow:'up' },
  { left:385, top:25, width:40, height:497, arrow:'down' },
  { left:515, top:25, width:40, height:497, arrow:'up' },
];

// Mismo orden que el HTML del plano: primero hilera 1 (5), hilera 2 (16),
// hilera 3 (19), hilera 4 (18), hilera 5 (7).
const SPOT_COORDS = [
  // Hilera 1 - trabajadores
  [64,43.5],[64,102.9],[64,162.3],[64,221.7],[64,281.1],
  // Hilera 2 - trabajadores
  [174,43.5],[214,67.5],[174,91.5],[214,115.5],[174,139.5],[214,163.5],
  [174,187.5],[214,211.5],[174,235.5],[214,259.5],[174,283.5],[214,307.5],
  [174,331.5],[214,355.5],[174,379.5],[214,403.5],
  // Hilera 3 - general
  [304,43.5],[344,67.5],[304,91.5],[344,115.5],[304,139.5],[344,163.5],
  [304,187.5],[344,211.5],[304,235.5],[344,259.5],[304,283.5],[344,307.5],
  [304,331.5],[344,355.5],[304,379.5],[344,403.5],[304,427.5],[344,451.5],[304,475.5],
  // Hilera 4 - general
  [434,43.5],[474,67.5],[434,91.5],[474,115.5],[434,139.5],[474,163.5],
  [434,187.5],[474,211.5],[434,235.5],[474,259.5],[434,283.5],[474,307.5],
  [434,331.5],[474,355.5],[434,379.5],[474,403.5],[434,427.5],[474,451.5],
  // Hilera 5 - general
  [584,43.5],[584,99.7],[584,155.8],[584,212.0],[584,268.1],[584,324.3],[584,380.5],
];

const ROW_SIZES = [5,16,19,18,7];

function buildSpots(){
  const spots = [];
  let idx = 0;
  ROW_SIZES.forEach((size, rowIdx) => {
    const rowNum = rowIdx + 1;
    const isWorkerRow = rowNum <= 2;
    for(let i=0;i<size;i++){
      const [left, top] = SPOT_COORDS[idx];
      const id = `H${rowNum}-${String(i+1).padStart(2,'0')}`;
      let state;
      if(isWorkerRow){
        // deja un par de espacios de trabajador ya liberados para la demo
        state = (idx % 9 === 0) ? 'trabajador-libre' : 'trabajador-ocupado';
      } else {
        const m = idx % 5;
        state = m === 0 ? 'ocupado' : (m === 1 ? 'reservado' : 'disponible');
      }
      spots.push({
        id, left, top, width:32, height:13, rotate:62,
        row: rowNum, worker: isWorkerRow,
        state, reservedBy: null, assignedWorkerId: null
      });
      idx++;
    }
  });
  return spots;
}

/* ---------------- Estado ---------------- */
function defaultState(){
  return {
    session: null,          // id del usuario con sesión activa
    users: [],              // {id, nombre, correo, rol, horarioInicio, horarioFin, horarioEscolar}
    vehicles: {},           // userId -> {marca, placa, onapafa, licencia} | {sinVehiculo:true,...}
    spots: buildSpots(),
    reservations: [],       // {id, userId, spotId, createdAt, expiresAt, status}
    accessLog: [],          // {type:'entrada'|'salida', userId, spotId, time}
    reports: [],            // {placa, motivo, descripcion, time, sancion, reporterId}
    notifications: [],      // {id, text, type, time, read}
    rides: [],               // publicaciones de aventón: {id,userId,nombre,rol,tipo,zona,horario,dias,asientos,notas,correo,activo}
    rideRequests: [],        // {id, rideId, fromUserId, status, createdAt}
    adminMode: false,
  };
}

let state = loadState();

function loadState(){
  let st = null;
  try{
    const raw = localStorage.getItem(LS_KEY);
    if(raw){
      st = JSON.parse(raw);
      // migración suave por si el estado guardado viene de una versión anterior
      st.rides = (st.rides || []).filter(r => !r.esDemo);
      const ids = new Set(st.rides.map(r => r.id));
      st.rideRequests = (st.rideRequests || []).filter(rq => ids.has(rq.rideId));
      st.reports = st.reports || [];
      st.notifications = st.notifications || [];
      migrarCuentasDemo(st);
    }
  }catch(e){ st = null; }
  if(!st) st = defaultState();
  // la sesión es por pestaña: así puedes tener dos cuentas abiertas a la vez
  st.session = sessionStorage.getItem('uatParkingSession_v1') || null;
  return st;
}
function saveState(){
  if(state.session) sessionStorage.setItem('uatParkingSession_v1', state.session);
  else sessionStorage.removeItem('uatParkingSession_v1');
  localStorage.setItem(LS_KEY, JSON.stringify(state));
}


function currentUser(){
  return state.users.find(u => u.id === state.session) || null;
}
function currentVehicle(){
  const u = currentUser();
  return u ? state.vehicles[u.id] || null : null;
}

/* ---------------- Utilidades ---------------- */
const $ = sel => document.querySelector(sel);
const $all = sel => Array.from(document.querySelectorAll(sel));

function fmtTime(ts){
  const d = new Date(ts);
  return d.toLocaleTimeString('es-MX', {hour:'2-digit', minute:'2-digit'});
}
function fmtClock(ms){
  if(ms < 0) ms = 0;
  const totalSec = Math.floor(ms/1000);
  const m = Math.floor(totalSec/60).toString().padStart(2,'0');
  const s = (totalSec%60).toString().padStart(2,'0');
  return `${m}:${s}`;
}
function uid(prefix){
  return prefix + '-' + Math.random().toString(36).slice(2,8);
}

function pushNotification(text, type='info', userId=state.session){
  state.notifications.unshift({
    id: uid('N'), userId, text, type, time: Date.now(), read:false
  });
  saveState();
  renderNotifBadge();
}

/* ---------------- Navegación entre vistas ---------------- */
function showView(name){
  const _u = currentUser();
  const _admin = !!_u && _u.rol === 'administrador';
  if(name === 'admin' && !_admin) name = _u ? 'home' : 'auth';
  if(!_u) name = 'auth';   // sin sesión solo se puede ver el acceso
  if(_admin && ['home','reservas','aventon','reportes','vehiculo'].includes(name)) name = 'admin';
  $all('.view').forEach(v => v.classList.remove('active'));
  const target = document.getElementById('view-' + name);
  if(target) target.classList.add('active');

  $all('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.goto === name));

  renderView(name);
  renderNotifBadge();

  window.scrollTo(0,0);
}

function renderView(name){
  if(name === 'home') renderHome();
  if(name === 'mapa') renderMap();
  if(name === 'reservas') renderReservas();
  if(name === 'reportes') renderReportes();
  if(name === 'aventon') renderAventon();
  if(name === 'notificaciones') renderNotificaciones();
  if(name === 'perfil') renderPerfil();
  if(name === 'admin') renderAdmin();
}

function afterLoginUI(){
  $('#bottomnav').hidden = false;
  $('#btnNotif').hidden = false;
  document.querySelector('.device').classList.remove('sin-menu');
  ajustarNavPorRol();
}
function beforeLoginUI(){
  $('#bottomnav').hidden = true;
  $('#btnNotif').hidden = true;
  document.querySelector('.device').classList.add('sin-menu');
}

/* ================================================================
   AUTENTICACIÓN
   ================================================================ */
function rolRegistro(){ return $('#rolSegment .seg.active').dataset.rol; }

function sincronizarCorreoAlumno(){
  if(rolRegistro() !== 'estudiante') return;
  const mat = $('#regId').value.trim().toLowerCase();
  const mail = $('#regCorreo');
  mail.value = mat ? `${mat}@${DOMINIO_ALUMNOS}` : '';
  mail.dataset.auto = '1';
}

function actualizarCamposRegistro(){
  const esAlumno = rolRegistro() === 'estudiante';
  $('#campoEstudiante').hidden = !esAlumno;
  $('#campoTrabajador').hidden = esAlumno;
  $('#lblRegId').textContent = esAlumno ? 'Matrícula' : 'Número de empleado';
  $('#lblDocumento').textContent = esAlumno ? 'Constancia de estudios' : 'Credencial o constancia laboral';
  const mail = $('#regCorreo');
  mail.readOnly = esAlumno;
  mail.placeholder = esAlumno ? `matricula@${DOMINIO_ALUMNOS}` : `nombre.apellido@${DOMINIO_DOCENTES}`;
  $('#hintCorreo').textContent = esAlumno ? `Se genera con tu matrícula: matricula@${DOMINIO_ALUMNOS}` : `Debe terminar en @${DOMINIO_DOCENTES}`;
  if(esAlumno) sincronizarCorreoAlumno();
  else if(mail.dataset.auto === '1'){ mail.value = ''; mail.dataset.auto = '0'; }
  mostrarErrores('regErrores', []);
}

function wireAuth(){
  $all('#authTabs .tab').forEach(tab=>{
    tab.addEventListener('click', ()=>{
      $all('#authTabs .tab').forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      $all('.pane').forEach(p=>p.classList.remove('active'));
      $(`[data-pane="${tab.dataset.tab}"]`).classList.add('active');
    });
  });

  $all('#rolSegment .seg').forEach(seg=>{
    seg.addEventListener('click', ()=>{
      $all('#rolSegment .seg').forEach(s=>s.classList.remove('active'));
      seg.classList.add('active');
      actualizarCamposRegistro();
    });
  });
  $('#regId').addEventListener('input', sincronizarCorreoAlumno);
  actualizarCamposRegistro();

  /* ---------- Inicio de sesión ---------- */
  $('#paneLogin').addEventListener('submit', e=>{
    e.preventDefault();
    const correo = $('#loginEmail').value.trim().toLowerCase();
    const clave = $('#loginPass').value;

    const espera = loginBloqueadoMs();
    if(espera > 0){
      mostrarErrores('loginError', [`Demasiados intentos fallidos. Intenta de nuevo en ${Math.ceil(espera / 1000)} segundos.`]);
      return;
    }
    if(!correo || !clave){
      mostrarErrores('loginError', ['Escribe tu correo institucional y tu contraseña.']);
      return;
    }

    const user = state.users.find(u => (u.correo || '').toLowerCase() === correo);
    if(user && !user.hash){
      mostrarErrores('loginError', ['Esta cuenta se creó con una versión anterior y no tiene contraseña. Crea una cuenta nueva o usa el modo demostración.']);
      return;
    }
    // se calcula el hash aunque la cuenta no exista, para que no se note la diferencia
    const calculado = hashPassword(clave, user ? user.sal : '00000000000000000000000000000000');
    if(!user || calculado !== user.hash){
      const restantes = registrarFalloLogin();
      mostrarErrores('loginError', [restantes > 0
        ? `Correo o contraseña incorrectos. Te quedan ${restantes} intento(s).`
        : `Demasiados intentos fallidos. La entrada se bloquea ${Math.round(BLOQUEO_LOGIN_MS / 1000)} segundos.`]);
      $('#loginPass').value = '';
      return;
    }

    limpiarFallosLogin();
    mostrarErrores('loginError', []);
    $('#loginPass').value = '';
    state.session = user.id;
    saveState();
    pushNotification(`Bienvenido de nuevo, ${user.nombre}.`, 'ok');
    routeAfterAuth();
  });

  /* ---------- Registro ---------- */
  $('#paneRegistro').addEventListener('submit', e=>{
    e.preventDefault();
    const rol = rolRegistro();
    const id = $('#regId').value.trim();
    const nombre = $('#regNombre').value.replace(/\s+/g, ' ').trim();
    const correo = $('#regCorreo').value.trim().toLowerCase();
    const clave = $('#regPass').value;
    const clave2 = $('#regPass2').value;
    const archivo = $('#regConstancia').files[0];

    const errores = [];
    const eId = validarIdentificador(rol, id);
    if(eId) errores.push(eId);
    const eNombre = validarNombrePersona(nombre);
    if(eNombre) errores.push(eNombre);
    // para alumnos el correo depende de la matrícula; si la matrícula es inválida no se compara
    if(rol === 'trabajador' || !eId){
      const eCorreo = validarCorreoInstitucional(rol, correo, id);
      if(eCorreo) errores.push(eCorreo);
    }
    if(!eId && state.users.some(u => String(u.id).toLowerCase() === id.toLowerCase())){
      errores.push('Ya existe una cuenta con esa matrícula o número de empleado. Inicia sesión.');
    }
    if(state.users.some(u => (u.correo || '').toLowerCase() === correo)){
      errores.push('Ya existe una cuenta con ese correo.');
    }
    errores.push(...validarContrasena(clave, id, correo));
    if(clave !== clave2) errores.push('Las contraseñas no coinciden.');
    if(rol === 'trabajador'){
      const ini = $('#regHorarioInicio').value, fin = $('#regHorarioFin').value;
      if(!ini || !fin || ini >= fin) errores.push('El horario laboral debe tener una hora de salida posterior a la de entrada.');
    }
    const eArchivo = validarArchivo(archivo);
    if(eArchivo) errores.push(eArchivo);

    if(errores.length){
      mostrarErrores('regErrores', errores);
      const box = $('#regErrores');
      if(box.scrollIntoView) box.scrollIntoView({ block:'center', behavior:'smooth' });
      return;
    }
    mostrarErrores('regErrores', []);

    const user = {
      id, nombre, correo, rol, ...credenciales(clave),
      estadoCuenta: 'pendiente',
      registro: Date.now(),
      documento: { nombre: archivo.name.slice(0, 80), tipo: archivo.type, tamano: archivo.size },
    };
    if(rol === 'estudiante'){
      user.horarioEscolar = $('#regHorarioEscolar').value;
    } else {
      user.horarioInicio = $('#regHorarioInicio').value;
      user.horarioFin = $('#regHorarioFin').value;
      // el espacio de trabajador se asigna cuando la administración valida la cuenta
    }

    state.users.push(user);
    state.session = id;
    saveState();
    pushNotification('Cuenta creada. Está pendiente de validación por la administración. Registra tu vehículo para terminar.', 'ok');
    state.users.filter(u => u.rol === 'administrador').forEach(a =>
      pushNotification(`Nueva cuenta por validar: ${nombre}.`, 'info', a.id));
    e.target.reset();
    actualizarCamposRegistro();
    showView('vehiculo');
  });
}

function routeAfterAuth(){
  if(esAdmin()){
    afterLoginUI();
    showView('admin');
    return;
  }
  const v = currentVehicle();
  if(!v){
    showView('vehiculo');
  } else {
    afterLoginUI();
    showView('home');
  }
}

/* ================================================================
   VEHÍCULO
   ================================================================ */
function wireVehiculo(){
  $('#sinVehiculo').addEventListener('change', e=>{
    $('#formVehiculo').hidden = e.target.checked;
    $('#formSinVehiculo').hidden = !e.target.checked;
  });

  $('#formVehiculo').addEventListener('submit', e=>{
    e.preventDefault();
    const u = currentUser();
    if(!u) return;
    const marca = $('#vehMarca').value.replace(/\s+/g, ' ').trim();
    const placaIn = $('#vehPlaca').value.trim();
    const licencia = $('#vehLicencia').value.trim().toUpperCase();

    const errores = [];
    if(marca.length < 3 || marca.length > 60 || /^\d+$/.test(marca)) errores.push('Escribe la marca y el modelo de tu vehículo (ej. Nissan Versa 2019).');
    const ePlaca = validarPlaca(placaIn);
    if(ePlaca) errores.push(ePlaca);
    const eLic = validarLicencia(licencia);
    if(eLic) errores.push(eLic);

    // una placa y una licencia solo pueden pertenecer a una cuenta
    const otros = Object.entries(state.vehicles).filter(([uid, v]) => uid !== u.id && !v.sinVehiculo);
    if(!ePlaca && otros.some(([, v]) => clavePlaca(v.placa) === clavePlaca(placaIn))){
      errores.push('Esa placa ya está registrada en otra cuenta. Si es tuya, acude con la administración.');
    }
    if(!eLic && otros.some(([, v]) => String(v.licencia).toUpperCase() === licencia)){
      errores.push('Ese número de licencia ya está registrado en otra cuenta.');
    }

    if(errores.length){ mostrarErrores('vehErrores', errores); return; }
    mostrarErrores('vehErrores', []);

    state.vehicles[u.id] = {
      sinVehiculo: false,
      marca,
      placa: normalizarPlaca(placaIn),
      onapafa: $('#vehOnapafa').checked,
      licencia,
    };
    saveState();
    pushNotification('Vehículo registrado y asociado a tu cuenta.', 'ok');
    afterLoginUI();
    showView('home');
  });

  $('#formSinVehiculo').addEventListener('submit', e=>{
    e.preventDefault();
    const u = currentUser();
    if(!u) return;
    state.vehicles[u.id] = {
      sinVehiculo: true,
      medio: $('#sinVehMedio').value,
      comentario: $('#sinVehComentario').value.trim().slice(0, 300),
    };
    saveState();
    pushNotification('Gracias por avisarnos, no necesitas un espacio de auto.', 'ok');
    afterLoginUI();
    showView('home');
  });
}

/* ================================================================
   HOME
   ================================================================ */
function drawQr(canvas, seed){
  const ctx = canvas.getContext('2d');
  const size = canvas.width;
  const cells = 12;
  const cell = size/cells;
  ctx.clearRect(0,0,size,size);
  ctx.fillStyle = '#fff';
  ctx.fillRect(0,0,size,size);

  // hash simple determinista a partir del texto
  let h = 0;
  for(let i=0;i<seed.length;i++){ h = (h*31 + seed.charCodeAt(i)) >>> 0; }

  ctx.fillStyle = '#2B1710';
  for(let y=0;y<cells;y++){
    for(let x=0;x<cells;x++){
      h = (h*1103515245 + 12345) >>> 0;
      if((h >> 5) % 3 === 0){
        ctx.fillRect(x*cell, y*cell, cell-1.5, cell-1.5);
      }
    }
  }
  // marcos estilo QR en las esquinas
  [[0,0],[cells-3,0],[0,cells-3]].forEach(([cx,cy])=>{
    ctx.fillStyle = '#2B1710';
    ctx.fillRect(cx*cell, cy*cell, cell*3-1.5, cell*3-1.5);
    ctx.fillStyle = '#fff';
    ctx.fillRect(cx*cell+cell*0.5, cy*cell+cell*0.5, cell*2-1.5, cell*2-1.5);
    ctx.fillStyle = '#2B1710';
    ctx.fillRect(cx*cell+cell*1, cy*cell+cell*1, cell-1.5, cell-1.5);
  });
}

function activeReservation(){
  const u = currentUser();
  if(!u) return null;
  return state.reservations.find(r => r.userId === u.id && (r.status === 'activa' || r.status === 'estacionado')) || null;
}

function spotById(id){ return state.spots.find(s => s.id === id); }

function freeStateFor(spot){
  return spot.worker ? 'trabajador-libre' : 'disponible';
}

function renderHome(){
  const u = currentUser();
  if(!u) return;
  $('#homeNombre').textContent = u.nombre;
  $('#homeRolChip').textContent = rolLabel(u.rol);
  $('#qrId').textContent = 'ID: ' + u.id;
  drawQr($('#qrCanvas'), u.id + '|' + (currentVehicle()?.placa || ''));

  const msgCuenta = mensajeCuenta(u);
  const aviso = $('#avisoCuenta');
  aviso.hidden = !msgCuenta;
  aviso.innerHTML = msgCuenta
    ? `<strong>${u.estadoCuenta === 'pendiente' ? 'Cuenta pendiente de validación' : 'Cuenta no validada'}</strong><p class="small">${esc(msgCuenta)}</p>`
    : '';

  // reservación activa
  const res = activeReservation();
  const card = $('#reservaActivaCard');
  if(res){
    card.hidden = false;
    $('#homeSpotId').textContent = res.spotId;
    renderReservaAcciones(res, $('#homeAccionesReserva'));
    tickHomeTimer();
  } else {
    card.hidden = true;
  }

  // tarjeta de trabajador
  const workerCard = $('#trabajadorCard');
  if(u.rol === 'trabajador' && u.workerSpotId){
    workerCard.hidden = false;
    $('#workerSpotId').textContent = u.workerSpotId;
    $('#workerHorario').textContent = `${u.horarioInicio} – ${u.horarioFin}`;
    const spot = spotById(u.workerSpotId);
    const liberado = spot.state === 'trabajador-libre';
    $('#btnLiberarEspacio').textContent = liberado ? 'Marcar como ocupado de nuevo' : 'Liberar mi espacio ahora';
    $('#workerEstadoTexto').textContent = liberado
      ? 'Tu espacio está disponible temporalmente para estudiantes.'
      : 'Tu espacio está reservado para ti mientras trabajas.';
  } else {
    workerCard.hidden = true;
  }

  // mini stats
  const disp = state.spots.filter(s=>s.state==='disponible'||s.state==='trabajador-libre').length;
  const ocup = state.spots.filter(s=>s.state==='ocupado'||s.state==='trabajador-ocupado').length;
  const resv = state.spots.filter(s=>s.state==='reservado').length;
  $('#miniStats').innerHTML = `
    <div class="mini-stat"><b>${disp}</b><span>Disponibles</span></div>
    <div class="mini-stat"><b>${resv}</b><span>Reservados</span></div>
    <div class="mini-stat"><b>${ocup}</b><span>Ocupados</span></div>
  `;
}

function renderReservaAcciones(res, container){
  container.innerHTML = '';
  if(res.status === 'activa'){
    const btnEntrar = document.createElement('button');
    btnEntrar.className = 'btn-primary';
    btnEntrar.textContent = 'Escanear QR · Entrada';
    btnEntrar.addEventListener('click', ()=>iniciarEscaneo('entrada'));
    const btnCancelar = document.createElement('button');
    btnCancelar.className = 'btn-secondary';
    btnCancelar.textContent = 'Cancelar reservación';
    btnCancelar.addEventListener('click', ()=>cancelarReservacion(res, true));
    container.appendChild(btnEntrar);
    container.appendChild(btnCancelar);
  } else if(res.status === 'estacionado'){
    const btnSalir = document.createElement('button');
    btnSalir.className = 'btn-primary';
    btnSalir.textContent = 'Escanear QR · Salida';
    btnSalir.addEventListener('click', ()=>iniciarEscaneo('salida'));
    container.appendChild(btnSalir);
  }
}

/* ---------------- Pantalla de escaneo (entrada / salida) ---------------- */
const CHECK_ICON_SVG = `<svg viewBox="0 0 24 24" width="24" height="24"><path d="M9 16.2 4.8 12l-1.4 1.4L9 19 20.6 7.4 19.2 6z" fill="currentColor"/></svg>`;

function iniciarEscaneo(tipo){
  const res = activeReservation();
  const u = currentUser();
  if(!res || !u) return;
  const spot = spotById(res.spotId);
  if(!spot) return;

  $('#modalTitle').textContent = tipo === 'entrada' ? 'Escaneo de entrada' : 'Escaneo de salida';
  $('#modalBody').innerHTML = `
    <div class="scan-stage" id="scanStage">
      <div class="scan-frame">
        <canvas id="scanCanvas" width="200" height="200"></canvas>
        <div class="scan-line"></div>
        <div class="corner tl"></div><div class="corner tr"></div>
        <div class="corner bl"></div><div class="corner br"></div>
      </div>
      <p class="scan-status" id="scanStatus">Acerca tu código al lector de la pluma… espacio ${spot.id}</p>
    </div>
  `;
  $('#modalActions').innerHTML = '';
  $('#modalOverlay').hidden = false;

  const canvas = $('#scanCanvas');
  if(canvas) drawQr(canvas, u.id + '|' + (currentVehicle()?.placa || '') + '|' + spot.id);

  setTimeout(()=>{
    const stage = $('#scanStage');
    if(!stage) return; // el usuario cerró el modal antes de tiempo
    stage.classList.add('scan-ok');
    const status = $('#scanStatus');
    if(status){
      status.innerHTML = `
        <span class="scan-check">${CHECK_ICON_SVG}</span>
        ${tipo === 'entrada'
          ? `Acceso validado. La pluma se abre para el espacio <strong>${spot.id}</strong>.`
          : `Salida validada. El espacio <strong>${spot.id}</strong> queda disponible.`}
      `;
    }
    setTimeout(()=>{
      if(tipo === 'entrada') registrarEntrada(); else registrarSalida();
      closeModal();
    }, 900);
  }, 1300);
}

function tickHomeTimer(){
  const res = activeReservation();
  if(!res || res.status !== 'activa'){
    if($('#homeTimer')) $('#homeTimer').textContent = '--:--';
    return;
  }
  $('#homeTimer').textContent = fmtClock(res.expiresAt - Date.now());
}

/* ================================================================
   MAPA / RESERVACIONES
   ================================================================ */
function renderMap(){
  const lot = $('#lot');
  lot.innerHTML = '';

  LANES.forEach(l=>{
    const div = document.createElement('div');
    div.className = 'lane';
    div.style.left = l.left+'px';
    div.style.top = l.top+'px';
    div.style.width = l.width+'px';
    div.style.height = l.height+'px';
    div.innerHTML = `<div class="lane-line"></div><div class="lane-arrow lane-arrow-${l.arrow}"></div>`;
    lot.appendChild(div);
  });

  const u = currentUser();
  state.spots.forEach(spot=>{
    const div = document.createElement('div');
    div.className = 'spot ' + spot.state;
    if(u && spot.reservedBy === u.id) div.classList.add('mine');
    div.style.left = spot.left + 'px';
    div.style.top = spot.top + 'px';
    div.style.width = spot.width + 'px';
    div.style.height = spot.height + 'px';
    div.style.transform = `rotate(${spot.rotate}deg)`;
    div.title = spot.id;
    div.addEventListener('click', ()=>openSpotModal(spot.id));
    lot.appendChild(div);
  });

  $('#lotCaption').innerHTML = ROW_SIZES.map((n,i)=>`<div>Hilera ${i+1}: ${n}</div>`).join('');

  scaleLot();
}

function scaleLot(){
  const wrap = $('.lot-wrap');
  const lot = $('#lot');
  if(!wrap || !lot) return;
  const scale = wrap.clientWidth / 680;
  lot.style.transform = `scale(${scale})`;
  wrap.style.height = (542*scale) + 'px';
}
window.addEventListener('resize', scaleLot);

function openSpotModal(spotId){
  const spot = spotById(spotId);
  const u = currentUser();
  const res = activeReservation();

  let title = `Espacio ${spot.id}`;
  let body = '';
  const actions = [];

  const esMio = res && res.spotId === spot.id;

  if(u && u.rol === 'administrador'){
    const estados = { disponible:'Disponible', reservado:'Reservado', ocupado:'Ocupado', 'trabajador-ocupado':'Destinado a trabajadores (ocupado)', 'trabajador-libre':'Espacio de trabajador liberado' };
    body = `<p class="muted">Estado actual: <strong>${estados[spot.state] || spot.state}</strong></p>`;
  } else if(esMio){
    body = `<p class="muted">Este es tu espacio reservado.</p>`;
    if(res.status === 'activa'){
      actions.push(['Cancelar reservación', ()=>{ closeModal(); cancelarReservacion(res, true); }, 'btn-secondary']);
    }
  } else if(!cuentaActiva(u)){
    body = `<p class="small">${esc(mensajeCuenta(u))}</p>`;
  } else if((spot.state === 'disponible' || spot.state === 'trabajador-libre') && !(currentVehicle() && !currentVehicle().sinVehiculo)){
    body = '<p>Para reservar necesitas un vehículo registrado en tu cuenta.</p>';
    actions.push(['Registrar vehículo', ()=>{ closeModal(); showView('vehiculo'); }, 'btn-primary']);
  } else if(spot.state === 'disponible' || spot.state === 'trabajador-libre'){
    const nota = spot.state === 'trabajador-libre'
      ? '<p class="muted small">Es un espacio de trabajador liberado temporalmente.</p>' : '';
    body = `<p>¿Reservar este lugar por ${RESERVA_MINUTOS} minutos?</p>${nota}`;
    actions.push(['Reservar espacio', ()=>{ closeModal(); reservarEspacio(spot.id); }, 'btn-primary']);
  } else if(spot.state === 'reservado'){
    body = `<p class="muted">Este espacio ya está reservado por otro usuario.</p>`;
  } else if(spot.state === 'trabajador-ocupado'){
    body = `<p class="muted">Espacio destinado a personal de la UAT. Solo disponible si el trabajador lo libera.</p>`;
  } else {
    body = `<p class="muted">Este espacio está ocupado actualmente.</p>`;
  }

  openModal(title, body, actions);
}

function reservarEspacio(spotId){
  const u = currentUser();
  if(!u) return;
  const spot = spotById(spotId);
  if(!spot) return;
  if(!exigirCuentaActiva()) return;

  const veh = currentVehicle();
  if(!veh || veh.sinVehiculo){
    openModal('Falta tu vehículo', '<p class="small">Para reservar necesitas un vehículo registrado en tu cuenta.</p>', [['Entendido', closeModal, 'btn-primary']]);
    return;
  }
  const bloqueo = bloqueoNoShowMs(u.id);
  if(bloqueo > 0){
    openModal('Reservas bloqueadas temporalmente',
      `<p class="small">Dejaste vencer 3 reservaciones en 24 horas. Podrás volver a reservar en ${fmtDuracion(bloqueo)}.</p>`,
      [['Entendido', closeModal, 'btn-primary']]);
    return;
  }
  if(!(spot.state === 'disponible' || spot.state === 'trabajador-libre')){
    openModal('Espacio no disponible', '<p class="small">Alguien más tomó este lugar. Elige otro.</p>', [['Entendido', closeModal, 'btn-primary']]);
    renderMap();
    return;
  }

  const previa = activeReservation();
  if(previa){
    cancelarReservacion(previa, false);
  }

  spot.state = 'reservado';
  spot.reservedBy = u.id;

  const reservation = {
    id: uid('R'),
    userId: u.id,
    spotId: spot.id,
    createdAt: Date.now(),
    expiresAt: Date.now() + RESERVA_MINUTOS*60*1000,
    status: 'activa',
  };
  state.reservations.push(reservation);
  saveState();
  pushNotification(`Reservaste el espacio ${spot.id}. Tienes ${RESERVA_MINUTOS} minutos para llegar.`, 'ok');
  renderMap();
  renderHome();
  renderReservas();
}

function liberarSpotAEstadoBase(spot){
  spot.state = freeStateFor(spot);
  spot.reservedBy = null;
}

function cancelarReservacion(res, manual){
  const spot = spotById(res.spotId);
  if(spot) liberarSpotAEstadoBase(spot);
  res.status = manual ? 'cancelada' : 'reemplazada';
  saveState();
  if(manual) pushNotification(`Cancelaste tu reservación del espacio ${res.spotId}.`, 'warn');
  renderMap();
  renderHome();
  renderReservas();
}

function registrarEntrada(){
  const res = activeReservation();
  if(!res || res.status !== 'activa') return;
  const spot = spotById(res.spotId);
  res.status = 'estacionado';
  spot.state = 'ocupado';
  state.accessLog.push({type:'entrada', userId:res.userId, spotId:res.spotId, time:Date.now()});
  saveState();
  pushNotification(`Entrada registrada en el espacio ${res.spotId}.`, 'ok');
  renderMap(); renderHome(); renderReservas();
}

function registrarSalida(){
  const res = activeReservation();
  if(!res || res.status !== 'estacionado') return;
  const spot = spotById(res.spotId);
  liberarSpotAEstadoBase(spot);
  res.status = 'finalizada';
  state.accessLog.push({type:'salida', userId:res.userId, spotId:res.spotId, time:Date.now()});
  saveState();
  pushNotification(`Salida registrada. El espacio ${res.spotId} quedó disponible.`, 'ok');
  renderMap(); renderHome(); renderReservas();
}

function checkExpiraciones(){
  const now = Date.now();
  let changed = false;
  state.reservations.forEach(r=>{
    if(r.status === 'activa' && !r.avisoVencimiento && (r.expiresAt - now) <= 5*60*1000 && (r.expiresAt - now) > 0){
      r.avisoVencimiento = true;
      changed = true;
      if(r.userId === state.session){
        const minutos = Math.max(1, Math.ceil((r.expiresAt - now)/60000));
        pushNotification(`Tu reservación del espacio ${r.spotId} está por vencer. Quedan ${minutos} min para llegar.`, 'warn');
      }
    }
    if(r.status === 'activa' && r.expiresAt <= now){
      const spot = spotById(r.spotId);
      if(spot) liberarSpotAEstadoBase(spot);
      r.status = 'expirada';
      changed = true;
      if(r.userId === state.session){
        pushNotification(`Tu reservación del espacio ${r.spotId} expiró y el lugar volvió a estar disponible.`, 'danger');
      }
    }
  });
  if(changed){
    saveState();
    if(document.getElementById('view-mapa').classList.contains('active')) renderMap();
    if(document.getElementById('view-reservas').classList.contains('active')) renderReservas();
  }
}

/* ================================================================
   RESERVAS (vista)
   ================================================================ */
function renderReservas(){
  const u = currentUser();
  const detalle = $('#reservaCardDetalle');
  const res = activeReservation();

  if(res){
    const spot = spotById(res.spotId);
    detalle.innerHTML = `
      <div class="card-head-row"><h3>Espacio ${spot.id}</h3>${res.status==='activa' ? `<span class="timer" id="reservasTimer">${fmtClock(res.expiresAt-Date.now())}</span>`:''}</div>
      <p class="muted small">Estado: ${res.status === 'activa' ? 'Esperando que llegues' : 'Estacionado'}</p>
      <div class="btn-row" id="reservasAcciones"></div>
    `;
    renderReservaAcciones(res, $('#reservasAcciones'));
  } else {
    detalle.innerHTML = `<p class="muted">No tienes una reservación activa. Ve al mapa para reservar un lugar.</p>`;
  }

  const historial = state.reservations
    .filter(r => u && r.userId === u.id && !['activa','estacionado'].includes(r.status))
    .sort((a,b)=>b.createdAt-a.createdAt);

  const cont = $('#historialReservas');
  if(historial.length === 0){
    cont.innerHTML = `<p class="empty-note">Aún no tienes historial de reservas.</p>`;
    return;
  }
  const estadoTag = {
    finalizada: ['ok','Completada'],
    cancelada: ['warn','Cancelada'],
    expirada: ['danger','Expiró'],
    reemplazada: ['info','Reemplazada'],
  };
  cont.innerHTML = historial.map(r=>{
    const [cls,label] = estadoTag[r.status] || ['info', r.status];
    return `<div class="list-item">
      <div class="list-item-head"><strong>Espacio ${r.spotId}</strong><time>${fmtTime(r.createdAt)}</time></div>
      <span class="tag ${cls}">${label}</span>
    </div>`;
  }).join('');
}

/* ================================================================
   REPORTES
   ================================================================ */
function sancionPorConteo(n){
  if(n === 1) return 'Advertencia';
  if(n === 2) return '1 día de sanción';
  if(n === 3) return '2 días de sanción';
  return 'Revisión por administración';
}

function wireReportes(){
  $('#formReporte').addEventListener('submit', e=>{
    e.preventDefault();
    const u = currentUser();
    if(!u || !exigirCuentaActiva()) return;
    const placaIn = $('#repPlaca').value.trim();
    const motivo = $('#repMotivo').value;
    const descripcion = $('#repDescripcion').value.replace(/\s+/g, ' ').trim();
    const DIA = 24 * 3600 * 1000;

    const errores = [];
    const ePlaca = validarPlaca(placaIn);
    if(ePlaca) errores.push(ePlaca);
    if(descripcion.length < 10) errores.push('Describe lo ocurrido con al menos 10 caracteres.');
    if(descripcion.length > 300) errores.push('La descripción no puede pasar de 300 caracteres.');
    if(!ePlaca){
      const clave = clavePlaca(placaIn);
      const mia = currentVehicle();
      if(mia && !mia.sinVehiculo && clavePlaca(mia.placa) === clave) errores.push('No puedes reportar tu propio vehículo.');
      if(state.reports.some(r => r.reporterId === u.id && clavePlaca(r.placa) === clave && Date.now() - r.time < DIA)){
        errores.push('Ya reportaste esa placa en las últimas 24 horas.');
      }
    }
    if(state.reports.filter(r => r.reporterId === u.id && Date.now() - r.time < DIA).length >= 5){
      errores.push('Alcanzaste el máximo de 5 reportes en 24 horas.');
    }
    if(errores.length){ mostrarErrores('repErrores', errores); return; }
    mostrarErrores('repErrores', []);

    const placa = normalizarPlaca(placaIn);
    const conteo = state.reports.filter(r => clavePlaca(r.placa) === clavePlaca(placa)).length + 1;
    const sancion = sancionPorConteo(conteo);

    state.reports.push({
      id: uid('REP'), placa, motivo, descripcion, time: Date.now(),
      reporterId: u.id, conteo, sancion
    });
    saveState();
    pushNotification(`Reporte enviado para ${placa}. Resultado preliminar: ${sancion}.`, 'warn');
    e.target.reset();
    renderReportes();
  });
}

function renderReportes(){
  const cont = $('#listaReportes');
  const ordenados = [...state.reports].sort((a,b)=>b.time-a.time);
  if(ordenados.length === 0){
    cont.innerHTML = `<p class="empty-note">No hay reportes registrados todavía.</p>`;
    return;
  }
  cont.innerHTML = ordenados.map(r=>`
    <div class="list-item">
      <div class="list-item-head"><strong>${esc(r.placa)}</strong><time>${fmtTime(r.time)}</time></div>
      <p class="muted small" style="margin-bottom:6px;">${esc(r.motivo)} — ${esc(r.descripcion)}</p>
      <span class="tag warn">${r.sancion}</span>
    </div>
  `).join('');
}

/* ================================================================
   AVENTÓN COMPARTIDO
   Funciona entre cuentas distintas: abre otra pestaña, inicia sesión
   con otra cuenta y verás las solicitudes, respuestas y mensajes.
   ================================================================ */
const SESSION_KEY = 'uatParkingSession_v1';

function esc(s){
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function userById(id){ return state.users.find(u => u.id === id) || null; }
function normTxt(s){
  return (s||'').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g,'')
    .replace(/\b(col|colonia|fracc|fraccionamiento)\.?\s/g,'').replace(/[^a-z0-9 ]/g,' ').replace(/\s+/g,' ').trim();
}
function minutosDe(hhmm){ const [h,m] = (hhmm||'0:0').split(':').map(Number); return h*60 + m; }

function misRide(){
  const u = currentUser();
  return u ? state.rides.find(r => r.userId === u.id && r.activo) || null : null;
}
function asientosLibres(ride){
  if(ride.tipo !== 'ofrezco') return null;
  const tomados = state.rideRequests.filter(rq => rq.rideId === ride.id && rq.status === 'aceptada').length;
  return Math.max(0, ride.asientos - tomados);
}
function reputacion(userId){
  let sum = 0, n = 0;
  state.rideRequests.forEach(rq=>{
    Object.entries(rq.ratings || {}).forEach(([rater, val])=>{
      const target = rater === rq.fromUserId ? rq.toUserId : rq.fromUserId;
      if(target === userId){ sum += val.stars; n++; }
    });
  });
  return { avg: n ? sum/n : null, n };
}
function ratingHtml(userId){
  const rep = reputacion(userId);
  return rep.n ? `<span class="rating">★ ${rep.avg.toFixed(1)} (${rep.n})</span>` : `<span class="muted small">Sin calificaciones</span>`;
}
function compatibilidad(mine, r){
  const comunes = r.dias.filter(d => mine.dias.includes(d));
  const diff = Math.abs(minutosDe(mine.horario) - minutosDe(r.horario));
  let pts = Math.round(50 * comunes.length / Math.max(mine.dias.length, r.dias.length, 1));
  pts += diff <= 15 ? 30 : diff <= 30 ? 20 : diff <= 60 ? 10 : 0;
  const zm = normTxt(mine.zona), zr = normTxt(r.zona);
  const mismaZona = !!zm && !!zr && (zm === zr || zm.includes(zr) || zr.includes(zm));
  if(mismaZona) pts += 20;
  return { pts, comunes, diff, mismaZona, compatible: comunes.length > 0 && diff <= 60 };
}
function solicitudActiva(rideId, userId){
  return state.rideRequests.find(rq => rq.rideId === rideId && rq.fromUserId === userId && (rq.status === 'pendiente' || rq.status === 'aceptada')) || null;
}
function rideDe(rq){ return state.rides.find(r => r.id === rq.rideId) || null; }

function mostrarTabAventon(name){
  $all('#aventonTabs .tab').forEach(t => t.classList.toggle('active', t.dataset.vtab === name));
  $all('#view-aventon .vpane').forEach(p => p.classList.toggle('active', p.dataset.vpane === name));
}

function wireAventon(){
  $all('#aventonTabs .tab').forEach(tab=>{
    tab.addEventListener('click', ()=> mostrarTabAventon(tab.dataset.vtab));
  });

  $all('#aventonTipoSeg .seg').forEach(seg=>{
    seg.addEventListener('click', ()=>{
      $all('#aventonTipoSeg .seg').forEach(s=>s.classList.remove('active'));
      seg.classList.add('active');
      $('#aventonAsientosWrap').hidden = seg.dataset.tipo !== 'ofrezco';
    });
  });
  $all('#aventonDias .seg-day').forEach(d=> d.addEventListener('click', ()=> d.classList.toggle('active')));

  $('#formAventon').addEventListener('submit', guardarPublicacion);
  $('#btnCancelarRide').addEventListener('click', cancelarPublicacion);
  $('#btnEditarRide').addEventListener('click', ()=>{
    rellenarFormulario(misRide());
    $('#rideResumen').hidden = true;
    $('#formAventon').hidden = false;
  });
  $('#filtroCompatibles').addEventListener('change', renderAventonExplorar);

  $('#view-aventon').addEventListener('click', e=>{
    const b = e.target.closest('[data-act]');
    if(b) manejarAccionAventon(b.dataset.act, b.dataset.id);
  });
}

function rellenarFormulario(r){
  if(!r) return;
  $all('#aventonTipoSeg .seg').forEach(s => s.classList.toggle('active', s.dataset.tipo === r.tipo));
  $('#aventonAsientosWrap').hidden = r.tipo !== 'ofrezco';
  $('#aventonZona').value = r.zona;
  $('#aventonHorario').value = r.horario;
  $all('#aventonDias .seg-day').forEach(d => d.classList.toggle('active', r.dias.includes(d.dataset.day)));
  $('#aventonAsientos').value = r.asientos || 2;
  $('#aventonPunto').value = r.punto || '';
  $('#aventonNotas').value = r.notas || '';
}

function guardarPublicacion(e){
  e.preventDefault();
  const u = currentUser();
  if(!u) return;
  if(!exigirCuentaActiva()) return;
  const tipo = $('#aventonTipoSeg .seg.active').dataset.tipo;
  const data = {
    tipo,
    zona: $('#aventonZona').value.trim(),
    horario: $('#aventonHorario').value,
    dias: $all('#aventonDias .seg-day.active').map(d => d.dataset.day),
    asientos: tipo === 'ofrezco' ? (parseInt($('#aventonAsientos').value, 10) || 1) : null,
    punto: $('#aventonPunto').value.trim(),
    notas: $('#aventonNotas').value.trim(),
  };
  if(!data.zona || !data.horario || !data.punto || data.dias.length === 0){
    alert('Completa zona, horario, punto de encuentro y al menos un día.');
    return;
  }

  if(data.zona.length < 3 || data.zona.length > 60 || data.punto.length < 3 || data.punto.length > 100 || data.notas.length > 200){
    alert('Revisa la longitud de los textos: zona (3 a 60), punto de encuentro (3 a 100) y notas (máximo 200).');
    return;
  }
  if(tipo === 'ofrezco'){
    const veh = currentVehicle();
    if(!veh || veh.sinVehiculo){ alert('Para ofrecer aventón necesitas un vehículo registrado en tu cuenta.'); return; }
    if(data.asientos < 1 || data.asientos > 6){ alert('Los lugares disponibles deben ser de 1 a 6.'); return; }
  }

  const mine = misRide();
  if(mine){
    const activas = state.rideRequests.filter(rq => rq.rideId === mine.id && ['pendiente','aceptada'].includes(rq.status));
    const aceptadas = activas.filter(rq => rq.status === 'aceptada').length;
    if(mine.tipo !== tipo && activas.length){
      alert('No puedes cambiar entre ofrecer y buscar mientras tengas solicitudes o viajes activos en esta ruta.');
      return;
    }
    if(tipo === 'ofrezco' && data.asientos < aceptadas){
      alert(`Ya tienes ${aceptadas} pasajero(s) aceptado(s); no puedes bajar de ese número de lugares.`);
      return;
    }
    Object.assign(mine, data);
    pushNotification('Actualizaste tu ruta de aventón.', 'ok');
  } else {
    state.rides.push({
      id: uid('RIDE'), userId:u.id, activo:true, createdAt:Date.now(),
      nombre:u.nombre, rol:u.rol, correo:u.correo, ...data
    });
    pushNotification('Publicaste tu ruta de aventón.', 'ok');
  }
  saveState();
  renderAventon();
  mostrarTabAventon('explorar');
}

function cancelarPublicacion(){
  const mine = misRide();
  const u = currentUser();
  if(!mine || !u) return;
  if(!confirm('¿Cancelar tu ruta? Se cancelarán también las solicitudes y viajes asociados.')) return;
  state.rideRequests.filter(rq => rq.rideId === mine.id && ['pendiente','aceptada'].includes(rq.status)).forEach(rq=>{
    rq.status = 'cancelada';
    pushNotification(`${u.nombre} canceló su ruta de aventón.`, 'warn', rq.fromUserId);
  });
  mine.activo = false;
  saveState();
  pushNotification('Cancelaste tu ruta de aventón.', 'info');
  renderAventon();
}

function manejarAccionAventon(act, id){
  const u = currentUser();
  if(!u) return;
  if(act === 'solicitar'){
    const ride = state.rides.find(r => r.id === id);
    if(!ride || ride.userId === u.id) return;
    openModal(`Solicitar a ${ride.nombre}`, `
      <p class="small muted">${ride.tipo === 'ofrezco' ? 'Pide un lugar en su viaje.' : 'Ofrécele un lugar en tu auto.'} Puedes escribir un mensaje (opcional).</p>
      <textarea id="solMensaje" maxlength="200" placeholder="Ej. Hola, entro a la misma hora que tú..."></textarea>
    `, [
      ['Enviar solicitud', ()=>{ const m = $('#solMensaje').value.trim(); closeModal(); crearSolicitud(id, m); }, 'btn-primary'],
      ['Cancelar', closeModal, 'btn-secondary'],
    ]);
  }
  else if(act === 'aceptar') responderSolicitud(id, true);
  else if(act === 'rechazar') responderSolicitud(id, false);
  else if(act === 'cancelar-sol') cancelarSolicitud(id);
  else if(act === 'chat') abrirChat(id);
  else if(act === 'calificar') abrirCalificacion(id);
  else if(act === 'cancelar-viaje') cancelarViaje(id);
}

function crearSolicitud(rideId, mensaje){
  const u = currentUser();
  const ride = state.rides.find(r => r.id === rideId);
  if(!u || !ride || !ride.activo) return;
  if(!exigirCuentaActiva()) return;
  if(solicitudActiva(rideId, u.id)) return;
  if(ride.tipo === 'ofrezco' && asientosLibres(ride) === 0){ alert('Esta ruta ya no tiene lugares.'); return; }

  state.rideRequests.push({
    id: uid('REQ'), rideId, fromUserId:u.id, toUserId:ride.userId, status:'pendiente', createdAt:Date.now(),
    messages: mensaje ? [{ from:u.id, text:mensaje, time:Date.now() }] : [], ratings:{}
  });
  saveState();
  pushNotification(`Enviaste una solicitud de aventón a ${ride.nombre}.`, 'ok');
  pushNotification(`${u.nombre} te envió una solicitud de aventón.`, 'info', ride.userId);
  renderAventon();
}

function responderSolicitud(id, aceptar){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  if(!u || !rq || rq.toUserId !== u.id || rq.status !== 'pendiente') return;
  const ride = rideDe(rq);
  if(!ride || !ride.activo){ alert('Esa ruta ya no está activa.'); return; }
  if(aceptar && ride.tipo === 'ofrezco' && asientosLibres(ride) === 0){
    alert('Ya no tienes lugares disponibles en esta ruta.');
    return;
  }
  rq.status = aceptar ? 'aceptada' : 'rechazada';
  saveState();
  pushNotification(
    aceptar ? `${u.nombre} aceptó tu solicitud. Ya puedes ver el punto de encuentro en Mis viajes.` : `${u.nombre} no pudo aceptar tu solicitud.`,
    aceptar ? 'ok' : 'warn', rq.fromUserId
  );
  pushNotification(aceptar ? 'Aceptaste la solicitud de aventón.' : 'Rechazaste la solicitud.', aceptar ? 'ok' : 'info');
  renderAventon();
}

function cancelarSolicitud(id){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  if(!u || !rq || rq.fromUserId !== u.id || rq.status !== 'pendiente') return;
  rq.status = 'cancelada';
  saveState();
  pushNotification(`${u.nombre} canceló su solicitud de aventón.`, 'info', rq.toUserId);
  renderAventon();
}

function cancelarViaje(id){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  if(!u || !rq || rq.status !== 'aceptada') return;
  if(rq.fromUserId !== u.id && rq.toUserId !== u.id) return;
  if(!confirm('¿Cancelar este viaje compartido?')) return;
  rq.status = 'cancelada';
  const otro = rq.fromUserId === u.id ? rq.toUserId : rq.fromUserId;
  saveState();
  pushNotification(`${u.nombre} canceló el viaje compartido.`, 'warn', otro);
  pushNotification('Cancelaste el viaje compartido.', 'info');
  renderAventon();
}

function abrirChat(id){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  if(!u || !rq) return;
  const otro = userById(rq.fromUserId === u.id ? rq.toUserId : rq.fromUserId);
  const msgs = (rq.messages || []).map(m => `
    <div class="chat-msg ${m.from === u.id ? 'mine' : ''}">${esc(m.text)}<time>${fmtTime(m.time)}</time></div>
  `).join('') || `<p class="empty-note">Aún no hay mensajes. Coordinen aquí los detalles del viaje.</p>`;

  openModal(`Chat con ${otro ? otro.nombre : 'usuario'}`,
    `<div class="chat-box" id="chatBox">${msgs}</div>
     <input type="text" id="chatInput" maxlength="200" placeholder="Escribe un mensaje">`,
    [['Enviar', ()=>enviarMensaje(id), 'btn-primary'], ['Cerrar', closeModal, 'btn-secondary']]);

  const box = $('#chatBox'); if(box) box.scrollTop = box.scrollHeight;
  const input = $('#chatInput');
  if(input){
    input.focus();
    input.addEventListener('keydown', ev => { if(ev.key === 'Enter'){ ev.preventDefault(); enviarMensaje(id); } });
  }
}

function enviarMensaje(id){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  const input = $('#chatInput');
  if(!u || !rq || !input) return;
  const texto = input.value.trim();
  if(!texto) return;
  rq.messages = rq.messages || [];
  rq.messages.push({ from:u.id, text:texto, time:Date.now() });
  const otro = rq.fromUserId === u.id ? rq.toUserId : rq.fromUserId;
  saveState();
  pushNotification(`Nuevo mensaje de ${u.nombre}.`, 'info', otro);
  abrirChat(id);
}

function abrirCalificacion(id){
  const u = currentUser();
  const rq = state.rideRequests.find(r => r.id === id);
  if(!u || !rq || (rq.ratings && rq.ratings[u.id])) return;
  openModal('Califica este viaje', `
    <label>Calificación
      <select id="ratingStars">
        <option value="5">★★★★★ Excelente</option>
        <option value="4">★★★★ Muy bien</option>
        <option value="3">★★★ Regular</option>
        <option value="2">★★ Mala</option>
        <option value="1">★ Muy mala</option>
      </select>
    </label>
    <label style="margin-top:10px;">Comentario (opcional)
      <textarea id="ratingComment" maxlength="200"></textarea>
    </label>
  `, [
    ['Guardar calificación', ()=>{
      rq.ratings = rq.ratings || {};
      rq.ratings[u.id] = { stars: parseInt($('#ratingStars').value, 10), comment: $('#ratingComment').value.trim(), time: Date.now() };
      const otro = rq.fromUserId === u.id ? rq.toUserId : rq.fromUserId;
      saveState();
      pushNotification(`${u.nombre} te calificó por el viaje compartido.`, 'info', otro);
      closeModal();
      renderAventon();
    }, 'btn-primary'],
    ['Cancelar', closeModal, 'btn-secondary'],
  ]);
}

/* ---------------- Render ---------------- */
function renderAventon(){
  const u = currentUser();
  if(!u) return;
  const mine = misRide();

  // impacto personal
  const viajes = state.rideRequests.filter(rq => rq.status === 'aceptada' && (rq.fromUserId === u.id || rq.toUserId === u.id));
  const conductorEn = viajes.filter(rq => { const r = rideDe(rq); return r && ((r.tipo === 'ofrezco' && r.userId === u.id) || (r.tipo === 'busco' && rq.fromUserId === u.id)); });
  $('#aventonImpacto').innerHTML = `
    <h3>Tu impacto</h3>
    <div class="mini-stats">
      <div class="mini-stat"><b>${viajes.length}</b><span>Viajes compartidos</span></div>
      <div class="mini-stat"><b>${conductorEn.length}</b><span>Como conductor</span></div>
      <div class="mini-stat"><b>${reputacion(u.id).avg ? reputacion(u.id).avg.toFixed(1) + ' ★' : '—'}</b><span>Tu reputación</span></div>
    </div>`;

  // insignia de solicitudes pendientes recibidas
  const pendientes = state.rideRequests.filter(rq => rq.toUserId === u.id && rq.status === 'pendiente').length;
  const badge = $('#tabBadgeSolicitudes');
  badge.hidden = pendientes === 0;
  badge.textContent = pendientes;

  // mi ruta
  if(mine){
    $('#rideResumen').hidden = false;
    $('#formAventon').hidden = true;
    const libres = asientosLibres(mine);
    $('#rideResumenBody').innerHTML = `
      <span class="tag ${mine.tipo === 'ofrezco' ? 'ok' : 'info'}">${mine.tipo === 'ofrezco' ? 'Ofreces aventón' : 'Buscas aventón'}</span>
      <p style="margin:8px 0 2px 0;">${esc(mine.zona)} · ${esc(mine.horario)} hrs</p>
      <p class="muted small" style="margin:0 0 6px 0;">${mine.dias.join(', ')}${libres !== null ? ` · ${libres} de ${mine.asientos} lugares libres` : ''}</p>
      <p class="muted small" style="margin:0;">Punto de encuentro: ${esc(mine.punto || '—')}</p>
      ${mine.notas ? `<p class="muted small" style="margin:6px 0 0 0;">"${esc(mine.notas)}"</p>` : ''}
    `;
  } else {
    $('#rideResumen').hidden = true;
    $('#formAventon').hidden = false;
  }

  renderAventonExplorar();
  renderAventonSolicitudes();
  renderAventonViajes();
}

function renderAventonExplorar(){
  const u = currentUser();
  if(!u) return;
  const mine = misRide();
  const soloCompat = $('#filtroCompatibles').checked && !!mine;

  let lista = state.rides
    .filter(r => r.activo && r.userId !== u.id && (!mine || r.tipo !== mine.tipo))
    .map(r => ({ r, comp: mine ? compatibilidad(mine, r) : null }));
  if(soloCompat) lista = lista.filter(x => x.comp.compatible);
  lista.sort((a,b)=> mine ? b.comp.pts - a.comp.pts : b.r.createdAt - a.r.createdAt);

  $('#explorarResumen').textContent = mine ? `${lista.length} resultado(s)` : 'Publica tu ruta para ver compatibilidad';

  $('#aventonMatches').innerHTML = lista.length ? lista.map(({r, comp})=>{
    const libres = asientosLibres(r);
    const rq = solicitudActiva(r.id, u.id);
    let accion;
    if(rq && rq.status === 'pendiente') accion = `<span class="tag warn">Solicitud enviada</span>`;
    else if(rq && rq.status === 'aceptada') accion = `<span class="tag ok">Aceptado · míralo en Mis viajes</span>`;
    else if(libres === 0) accion = `<span class="tag danger">Sin lugares</span>`;
    else accion = `<button class="btn-tiny solid" data-act="solicitar" data-id="${r.id}">${r.tipo === 'ofrezco' ? 'Pedir lugar' : 'Ofrecer aventón'}</button>`;
    const dias = r.dias.map(d => `<span class="day-chip ${comp && comp.comunes.includes(d) ? 'on' : ''}">${d}</span>`).join('');
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(r.nombre)}</strong><span class="tag info">${r.tipo === 'ofrezco' ? 'Ofrece' : 'Busca'}</span></div>
      <p class="muted small" style="margin:0 0 4px 0;">${rolLabel(r.rol)} · ${ratingHtml(r.userId)}</p>
      <p style="margin:0 0 6px 0; font-size:.88rem;">${esc(r.zona)} · ${esc(r.horario)} hrs${libres !== null ? ` · ${libres} lugar(es)` : ''}</p>
      <div>${dias}</div>
      ${r.notas ? `<p class="muted small" style="margin:4px 0 0 0;">"${esc(r.notas)}"</p>` : ''}
      ${comp ? `<div class="compat"><span style="width:${Math.min(100, comp.pts)}%"></span></div>
        <p class="muted small" style="margin:0;">${comp.pts}% compatible${comp.mismaZona ? ' · misma zona' : ''}${comp.diff <= 60 ? ` · ${comp.diff} min de diferencia` : ''}</p>` : ''}
      <div class="btn-tiny-row">${accion}</div>
    </div>`;
  }).join('') : `<p class="empty-note">${mine ? 'No hay rutas compatibles todavía. Desmarca "Solo compatibles" para ver todas.' : 'Todavía nadie ha publicado una ruta. ¡Sé el primero!'}</p>`;
}

function renderAventonSolicitudes(){
  const u = currentUser();
  if(!u) return;
  const recibidas = state.rideRequests.filter(rq => rq.toUserId === u.id).sort((a,b)=>b.createdAt - a.createdAt);
  const tagFor = { pendiente:['warn','Pendiente'], aceptada:['ok','Aceptada'], rechazada:['danger','Rechazada'], cancelada:['info','Cancelada'] };

  $('#aventonRecibidas').innerHTML = recibidas.length ? recibidas.map(rq=>{
    const de = userById(rq.fromUserId);
    const ride = rideDe(rq);
    const [cls, label] = tagFor[rq.status] || ['info', rq.status];
    const primer = (rq.messages || [])[0];
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(de ? de.nombre : 'Usuario')}</strong><time>${fmtTime(rq.createdAt)}</time></div>
      <p class="muted small" style="margin:0 0 4px 0;">${rolLabel(de ? de.rol : '')} · ${ratingHtml(rq.fromUserId)}${ride ? ` · para tu ruta de ${esc(ride.zona)}` : ''}</p>
      ${primer ? `<p class="muted small" style="margin:0 0 6px 0;">"${esc(primer.text)}"</p>` : ''}
      <span class="tag ${cls}">${label}</span>
      ${rq.status === 'pendiente' ? `<div class="btn-tiny-row">
        <button class="btn-tiny solid" data-act="aceptar" data-id="${rq.id}">Aceptar</button>
        <button class="btn-tiny danger" data-act="rechazar" data-id="${rq.id}">Rechazar</button>
      </div>` : ''}
    </div>`;
  }).join('') : `<p class="empty-note">Nadie te ha enviado solicitudes.</p>`;

  const enviadas = state.rideRequests.filter(rq => rq.fromUserId === u.id).sort((a,b)=>b.createdAt - a.createdAt);
  $('#aventonSolicitudes').innerHTML = enviadas.length ? enviadas.map(rq=>{
    const a = userById(rq.toUserId);
    const [cls, label] = tagFor[rq.status] || ['info', rq.status];
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(a ? a.nombre : 'Usuario')}</strong><time>${fmtTime(rq.createdAt)}</time></div>
      <span class="tag ${cls}">${label}</span>
      ${rq.status === 'pendiente' ? `<div class="btn-tiny-row"><button class="btn-tiny danger" data-act="cancelar-sol" data-id="${rq.id}">Cancelar solicitud</button></div>` : ''}
    </div>`;
  }).join('') : `<p class="empty-note">No has enviado solicitudes.</p>`;
}

function renderAventonViajes(){
  const u = currentUser();
  if(!u) return;
  const viajes = state.rideRequests
    .filter(rq => rq.status === 'aceptada' && (rq.fromUserId === u.id || rq.toUserId === u.id))
    .sort((a,b)=>b.createdAt - a.createdAt);

  $('#aventonViajes').innerHTML = viajes.length ? viajes.map(rq=>{
    const ride = rideDe(rq);
    const otro = userById(rq.fromUserId === u.id ? rq.toUserId : rq.fromUserId);
    const yoConductor = ride && ((ride.tipo === 'ofrezco' && ride.userId === u.id) || (ride.tipo === 'busco' && rq.fromUserId === u.id));
    const yaCalifique = rq.ratings && rq.ratings[u.id];
    const dias = ride ? ride.dias.map(d => `<span class="day-chip on">${d}</span>`).join('') : '';
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(otro ? otro.nombre : 'Usuario')}</strong><span class="tag ok">${yoConductor ? 'Tú conduces' : 'Tú eres pasajero'}</span></div>
      <p class="muted small" style="margin:0 0 6px 0;">${ratingHtml(otro ? otro.id : '')} · ${otro ? esc(otro.correo) : ''}</p>
      ${ride ? `<p style="margin:0 0 6px 0; font-size:.88rem;">${esc(ride.zona)} · ${esc(ride.horario)} hrs</p>
        <div>${dias}</div>
        <p class="muted small" style="margin:4px 0 0 0;">Punto de encuentro: <strong>${esc(ride.punto || '—')}</strong></p>` : ''}
      <div class="btn-tiny-row">
        <button class="btn-tiny solid" data-act="chat" data-id="${rq.id}">Chat</button>
        ${yaCalifique ? `<span class="tag info">Ya calificaste</span>` : `<button class="btn-tiny" data-act="calificar" data-id="${rq.id}">Calificar</button>`}
        <button class="btn-tiny danger" data-act="cancelar-viaje" data-id="${rq.id}">Cancelar viaje</button>
      </div>
    </div>`;
  }).join('') : `<p class="empty-note">Aún no tienes viajes compartidos. Explora rutas y envía una solicitud.</p>`;
}

/* ================================================================
   NOTIFICACIONES
   ================================================================ */
function misNotificaciones(){
  return state.notifications.filter(n => n.userId === state.session);
}

function renderNotifBadge(){
  const unread = misNotificaciones().filter(n=>!n.read).length;
  const badge = $('#notifBadge');
  badge.hidden = unread === 0;
  badge.textContent = unread > 9 ? '9+' : unread;
}

function renderNotificaciones(){
  const mias = misNotificaciones();
  mias.forEach(n=>n.read = true);
  saveState();
  renderNotifBadge();

  const cont = $('#listaNotificaciones');
  if(mias.length === 0){
    cont.innerHTML = `<p class="empty-note">No tienes notificaciones.</p>`;
    return;
  }
  const tagFor = {ok:'ok', warn:'warn', danger:'danger', info:'info'};
  cont.innerHTML = mias.map(n=>`
    <div class="list-item">
      <div class="list-item-head"><strong>${fmtTime(n.time)}</strong></div>
      <p style="margin:0;">${esc(n.text)}</p>
    </div>
  `).join('');
}

/* ================================================================
   PERFIL
   ================================================================ */
function renderPerfil(){
  const u = currentUser();
  if(!u) return;
  $('#perfilNombre').textContent = u.nombre;
  $('#perfilCorreo').textContent = u.correo;
  $('#perfilId').textContent = 'ID: ' + u.id + (u.estadoCuenta === 'pendiente' ? ' · Cuenta pendiente de validación' : (u.estadoCuenta === 'rechazada' ? ' · Cuenta no validada' : ''));
  $('#perfilRolChip').textContent = rolLabel(u.rol);

  const v = currentVehicle();
  const info = $('#perfilVehiculoInfo');
  if(!v){
    info.textContent = 'Sin vehículo registrado.';
  } else if(v.sinVehiculo){
    info.textContent = `Sin vehículo propio · Medio de transporte: ${v.medio}`;
  } else {
    info.innerHTML = `${esc(v.marca)}<br>Placa: ${esc(v.placa)}${v.onapafa ? ' (ONAPAFA)' : ''}`;
  }

  $('#perfilVehiculoCard').hidden = u.rol === 'administrador';
}

function wirePerfil(){
  $('#btnLogout').addEventListener('click', ()=>{
    state.session = null;
    saveState();
    beforeLoginUI();
    showView('auth');
  });

  $('#btnAcerca').addEventListener('click', ()=>{
    openModal('Acerca del proyecto', `
      <p class="small">Sistema digital para la gestión del estacionamiento de la UAT, tomando como punto de partida un estacionamiento cercano a la FCAV en el campus Victoria.</p>
      <p class="small"><strong>Objetivo general:</strong> gestionar y controlar el acceso al estacionamiento, mostrando disponibilidad, permitiendo reservar lugares y verificando que los usuarios pertenezcan a la comunidad universitaria.</p>
      <p class="small"><strong>Fases:</strong> 1) Registro y validación · 2) Acceso digital con QR · 3) Mapa y reservas · 4) Control y reportes · 5) Evaluación y expansión a otras áreas del campus.</p>
    `, [['Entendido', closeModal, 'btn-primary']]);
  });
}

function renderBottomNavForRole(){
  const adminBtn = $('#navAdminBtn');
  // el acceso a admin se hace desde Perfil > modo administración
}

/* ================================================================
   ADMIN
   ================================================================ */
let adminSearchTerm = '';

function wireAdmin(){
  $all('#adminTabs .tab').forEach(tab=>{
    tab.addEventListener('click', ()=>{
      $all('#adminTabs .tab').forEach(t=>t.classList.remove('active'));
      tab.classList.add('active');
      $all('.apane').forEach(p=>p.classList.remove('active'));
      $(`[data-apane="${tab.dataset.atab}"]`).classList.add('active');
    });
  });

  $('#adminValidaciones').addEventListener('click', e=>{
    const b = e.target.closest('[data-val]');
    if(!b || !esAdmin()) return;
    if(b.dataset.val === 'validar') validarCuenta(b.dataset.id); else rechazarCuenta(b.dataset.id);
  });

  $('#adminSearch').addEventListener('input', e=>{
    adminSearchTerm = e.target.value.trim().toLowerCase();
    renderAdmin(true);
  });

  // delegación para "marcar como resuelto" en reportes
  $('#adminReportes').addEventListener('click', e=>{
    const btn = e.target.closest('[data-resolve]');
    if(!btn) return;
    if(!esAdmin()) return;
    const rep = state.reports.find(r=>r.id === btn.dataset.resolve);
    if(rep){
      rep.resuelto = true;
      saveState();
      renderAdmin();
    }
  });
}

function matchesSearch(...fields){
  if(!adminSearchTerm) return true;
  return fields.some(f => (f||'').toString().toLowerCase().includes(adminSearchTerm));
}

/* ---------------- Validación de cuentas (administración) ---------------- */
function validarCuenta(id){
  const u = userById(id);
  if(!u || !esAdmin()) return;
  u.estadoCuenta = 'validada';
  if(u.rol === 'trabajador' && !u.workerSpotId){
    // el espacio de trabajador solo se asigna a cuentas ya validadas
    const libre = state.spots.find(s => s.worker && !s.assignedWorkerId);
    if(libre){ libre.assignedWorkerId = u.id; u.workerSpotId = libre.id; }
  }
  saveState();
  pushNotification('Tu cuenta fue validada. Ya puedes reservar, pedir aventón y enviar reportes.', 'ok', u.id);
  renderAdmin();
}

function rechazarCuenta(id){
  const u = userById(id);
  if(!u || !esAdmin()) return;
  if(!confirm(`¿Rechazar la cuenta de ${u.nombre}?`)) return;
  u.estadoCuenta = 'rechazada';
  saveState();
  pushNotification('Tu cuenta no pudo validarse. Acude con la administración del estacionamiento.', 'danger', u.id);
  renderAdmin();
}

function renderAdminValidaciones(){
  const pendientes = state.users.filter(u => u.estadoCuenta === 'pendiente');
  const badge = $('#tabBadgeValidaciones');
  badge.hidden = pendientes.length === 0;
  badge.textContent = pendientes.length;

  const lista = state.users
    .filter(u => (u.estadoCuenta === 'pendiente' || u.estadoCuenta === 'rechazada') && matchesSearch(u.nombre, u.id, u.correo))
    .sort((a, b) => (a.estadoCuenta === 'pendiente' ? 0 : 1) - (b.estadoCuenta === 'pendiente' ? 0 : 1) || (b.registro || 0) - (a.registro || 0));

  $('#adminValidaciones').innerHTML = lista.length ? lista.map(u => {
    const d = u.documento;
    const doc = d ? `${esc(d.nombre)} · ${Math.max(1, Math.round(d.tamano / 1024))} KB` : 'sin documento';
    const est = u.estadoCuenta === 'pendiente' ? '<span class="tag warn">Pendiente</span>' : '<span class="tag danger">Rechazada</span>';
    const horario = u.rol === 'estudiante' ? `Turno ${esc(u.horarioEscolar || '—')}` : `Horario ${esc(u.horarioInicio || '')}–${esc(u.horarioFin || '')}`;
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(u.nombre)}</strong><span class="tag info">${rolLabel(u.rol)}</span></div>
      <p class="muted small" style="margin:0 0 4px 0;">${esc(u.id)} · ${esc(u.correo)}</p>
      <p class="doc-info">${horario} · Documento: ${doc} · Registro: ${u.registro ? fmtTime(u.registro) : '—'}</p>
      ${est}
      <div class="btn-tiny-row">
        <button class="btn-tiny solid" data-val="validar" data-id="${esc(u.id)}">Validar cuenta</button>
        ${u.estadoCuenta === 'pendiente' ? `<button class="btn-tiny danger" data-val="rechazar" data-id="${esc(u.id)}">Rechazar</button>` : ''}
      </div>
    </div>`;
  }).join('') : `<p class="empty-note">No hay cuentas por validar.</p>`;
}

function renderAdminKpis(){
  const totalSpots = state.spots.length;
  const ocupados = state.spots.filter(s=>s.state==='ocupado'||s.state==='trabajador-ocupado').length;
  const pct = totalSpots ? Math.round(ocupados/totalSpots*100) : 0;
  const totalVehiculos = Object.values(state.vehicles).filter(v=>!v.sinVehiculo).length;
  const pendientes = state.reports.filter(r=>!r.resuelto).length;
  const viajesCompartidos = state.rideRequests.filter(rq=>rq.status==='aceptada').length;
  const porValidar = state.users.filter(u=>u.estadoCuenta==='pendiente').length;

  $('#adminKpis').innerHTML = `
    <div class="kpi"><b>${state.users.length}</b><span>Usuarios registrados</span></div>
    <div class="kpi"><b>${totalVehiculos}</b><span>Vehículos registrados</span></div>
    <div class="kpi"><b>${pct}%</b><span>Ocupación actual</span></div>
    <div class="kpi"><b>${pendientes}</b><span>Reportes pendientes</span></div>
    <div class="kpi"><b>${viajesCompartidos}</b><span>Viajes compartidos (≈ espacios ahorrados)</span></div>
    <div class="kpi"><b>${porValidar}</b><span>Cuentas por validar</span></div>
  `;
}

function renderAdminOcupacion(){
  let rows = '';
  for(let i=1;i<=5;i++){
    const spots = state.spots.filter(s=>s.row === i);
    const total = spots.length || 1;
    const ocupado = spots.filter(s=>s.state==='ocupado'||s.state==='trabajador-ocupado').length;
    const reservado = spots.filter(s=>s.state==='reservado').length;
    const pctOc = Math.round(ocupado/total*100);
    const pctRe = Math.round(reservado/total*100);
    const pctLi = Math.max(0, 100-pctOc-pctRe);
    const etiqueta = i<=2 ? `Hilera ${i} · trabajadores` : `Hilera ${i}`;
    rows += `
      <div class="ocup-row">
        <div class="ocup-label"><span>${etiqueta}</span><span class="muted small">${ocupado}/${spots.length} ocupados</span></div>
        <div class="ocup-bar">
          <span style="width:${pctOc}%; background:var(--danger)"></span>
          <span style="width:${pctRe}%; background:var(--warn)"></span>
          <span style="width:${pctLi}%; background:var(--ok)"></span>
        </div>
      </div>`;
  }
  $('#adminOcupacion').innerHTML = `<h3>Ocupación por hilera</h3>${rows}`;
}

function renderAdmin(soloLista=false){
  // al buscar solo se actualizan las listas, para no reiniciar las animaciones de los indicadores
  if(!soloLista){
    renderAdminKpis();
    renderAdminOcupacion();
  }

  renderAdminValidaciones();

  // Usuarios
  const usuarios = state.users.filter(u => matchesSearch(u.nombre, u.id, u.correo));
  $('#adminUsuarios').innerHTML = usuarios.length ? usuarios.map(u=>{
    const v = state.vehicles[u.id];
    const vehTag = !v ? ['warn','Sin vehículo registrado'] : (v.sinVehiculo ? ['info','Declaró sin vehículo'] : ['ok','Vehículo validado']);
    const est = u.estadoCuenta === 'pendiente' ? ['warn','Pendiente de validar'] : (u.estadoCuenta === 'rechazada' ? ['danger','Rechazada'] : ['ok','Cuenta validada']);
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(u.nombre)}</strong><span class="tag info">${rolLabel(u.rol)}</span></div>
      <p class="muted small" style="margin:0 0 6px 0;">${esc(u.id)} · ${esc(u.correo)}</p>
      <span class="tag ${est[0]}" style="margin-right:6px;">${est[1]}</span><span class="tag ${vehTag[0]}">${vehTag[1]}</span>
    </div>`;
  }).join('') : `<p class="empty-note">No se encontraron usuarios.</p>`;

  // Vehículos
  const vehEntries = Object.entries(state.vehicles).filter(([userId,v])=>{
    const u = state.users.find(x=>x.id===userId);
    return matchesSearch(u?.nombre, userId, v.placa);
  });
  $('#adminVehiculos').innerHTML = vehEntries.length ? vehEntries.map(([userId,v])=>{
    const u = state.users.find(x=>x.id===userId);
    const nombre = u ? u.nombre : userId;
    const desc = v.sinVehiculo ? `Sin vehículo · ${esc(v.medio)}` : `${esc(v.marca)} · Placa ${esc(v.placa)}${v.onapafa?' · ONAPAFA':''} · Licencia ${esc(v.licencia)}`;
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(nombre)}</strong></div>
      <p class="muted small" style="margin:0;">${desc}</p>
    </div>`;
  }).join('') : `<p class="empty-note">No se encontraron vehículos.</p>`;

  // Accesos
  const accesos = [...state.accessLog].sort((a,b)=>b.time-a.time).filter(a=>{
    const u = state.users.find(x=>x.id===a.userId);
    return matchesSearch(u?.nombre, a.userId, a.spotId);
  });
  $('#adminAccesos').innerHTML = accesos.length ? accesos.map(a=>{
    const u = state.users.find(x=>x.id===a.userId);
    const cls = a.type === 'entrada' ? 'ok' : 'info';
    return `<div class="list-item">
      <div class="list-item-head"><strong>${a.spotId}</strong><time>${fmtTime(a.time)}</time></div>
      <p class="muted small" style="margin:0 0 6px 0;">${esc(u ? u.nombre : a.userId)}</p>
      <span class="tag ${cls}">${a.type === 'entrada' ? 'Entrada' : 'Salida'}</span>
    </div>`;
  }).join('') : `<p class="empty-note">Sin registros de acceso.</p>`;

  // Reservas
  const reservas = [...state.reservations].sort((a,b)=>b.createdAt-a.createdAt).filter(r=>{
    const u = state.users.find(x=>x.id===r.userId);
    return matchesSearch(u?.nombre, r.userId, r.spotId);
  });
  const estadoTag = {
    activa:['warn','Esperando llegada'], estacionado:['ok','Estacionado'],
    finalizada:['ok','Completada'], cancelada:['info','Cancelada'],
    expirada:['danger','Expiró'], reemplazada:['info','Reemplazada'],
  };
  $('#adminReservas').innerHTML = reservas.length ? reservas.map(r=>{
    const u = state.users.find(x=>x.id===r.userId);
    const [cls,label] = estadoTag[r.status] || ['info', r.status];
    return `<div class="list-item">
      <div class="list-item-head"><strong>${r.spotId}</strong><time>${fmtTime(r.createdAt)}</time></div>
      <p class="muted small" style="margin:0 0 6px 0;">${esc(u ? u.nombre : r.userId)}</p>
      <span class="tag ${cls}">${label}</span>
    </div>`;
  }).join('') : `<p class="empty-note">Sin reservas registradas.</p>`;

  // Viajes compartidos
  const viajes = state.rides.filter(r => r.activo && matchesSearch(r.nombre, r.zona, r.correo));
  $('#adminViajes').innerHTML = viajes.length ? viajes.map(r=>{
    const aceptadas = state.rideRequests.filter(rq => rq.rideId === r.id && rq.status === 'aceptada').length;
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(r.nombre)}</strong><span class="tag ${r.tipo === 'ofrezco' ? 'ok' : 'info'}">${r.tipo === 'ofrezco' ? 'Ofrece' : 'Busca'}</span></div>
      <p class="muted small" style="margin:0 0 6px 0;">${esc(r.zona)} · ${esc(r.horario)} hrs · ${r.dias.join(', ')}${r.asientos ? ` · ${r.asientos} lugares` : ''}</p>
      <span class="tag ${aceptadas ? 'ok' : 'warn'}">${aceptadas} solicitud(es) aceptada(s)</span>
    </div>`;
  }).join('') : `<p class="empty-note">Sin publicaciones de aventón.</p>`;

  // Reportes
  const reportes = [...state.reports].sort((a,b)=>b.time-a.time).filter(r=>matchesSearch(r.placa));
  $('#adminReportes').innerHTML = reportes.length ? reportes.map(r=>{
    const urgente = r.conteo >= 4;
    const estadoTag = r.resuelto ? '<span class="tag ok">Resuelto</span>' : '<span class="tag warn">Pendiente</span>';
    return `<div class="list-item">
      <div class="list-item-head"><strong>${esc(r.placa)}</strong><time>${fmtTime(r.time)}</time></div>
      <p class="muted small" style="margin-bottom:6px;">${esc(r.motivo)} — ${esc(r.descripcion)}</p>
      <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
        <span class="tag ${urgente ? 'danger' : 'warn'}">Reporte #${r.conteo} · ${r.sancion}</span>
        ${estadoTag}
      </div>
      ${!r.resuelto ? `<button class="btn-tiny" data-resolve="${r.id}">Marcar como resuelto</button>` : ''}
    </div>`;
  }).join('') : `<p class="empty-note">No se encontraron reportes.</p>`;
}

/* ================================================================
   MODAL
   ================================================================ */
function openModal(title, bodyHtml, actions){
  $('#modalTitle').textContent = title;
  $('#modalBody').innerHTML = bodyHtml;
  const actionsEl = $('#modalActions');
  actionsEl.innerHTML = '';
  actions.forEach(([label, fn, cls])=>{
    const b = document.createElement('button');
    b.className = cls || 'btn-secondary';
    b.textContent = label;
    b.addEventListener('click', fn);
    actionsEl.appendChild(b);
  });
  if(actions.length === 0){
    const b = document.createElement('button');
    b.className = 'btn-secondary';
    b.textContent = 'Cerrar';
    b.addEventListener('click', closeModal);
    actionsEl.appendChild(b);
  }
  $('#modalOverlay').hidden = false;
}
function closeModal(){ $('#modalOverlay').hidden = true; }

/* ================================================================
   NAV GENERAL
   ================================================================ */
function wireNav(){
  document.addEventListener('click', e=>{
    const btn = e.target.closest('[data-goto]');
    if(btn) showView(btn.dataset.goto);
  });
  $all('.bottomnav .nav-item').forEach(b=>{
    b.addEventListener('click', ()=>showView(b.dataset.goto));
  });
  $('#btnNotif').addEventListener('click', ()=>showView('notificaciones'));
  $('#modalOverlay').addEventListener('click', e=>{
    if(e.target.id === 'modalOverlay') closeModal();
  });
}

function wireHomeExtra(){
  $('#btnLiberarEspacio').addEventListener('click', ()=>{
    const u = currentUser();
    if(!u || !u.workerSpotId) return;
    const spot = spotById(u.workerSpotId);
    if(spot.state === 'trabajador-ocupado'){
      spot.state = 'trabajador-libre';
      pushNotification(`Liberaste el espacio ${spot.id} para que un estudiante lo use.`, 'ok');
    } else if(spot.state === 'trabajador-libre'){
      spot.state = 'trabajador-ocupado';
      pushNotification(`Volviste a marcar el espacio ${spot.id} como ocupado.`, 'info');
    }
    saveState();
    renderHome();
    renderMap();
  });
}

/* ================================================================
   INICIALIZACIÓN
   ================================================================ */
/* ================================================================
   ROLES, ADMINISTRADOR Y MODO DEMOSTRACIÓN
   ================================================================ */
const DEMO_IDS = { estudiante:'20240001', trabajador:'E-1001', admin:'admin' };

function rolLabel(r){
  return r === 'trabajador' ? 'Trabajador' : (r === 'administrador' ? 'Administrador' : 'Estudiante');
}
function esAdmin(){
  const u = currentUser();
  return !!u && u.rol === 'administrador';
}

// cuenta de administración fija (no se puede crear desde el registro público)
function asegurarAdmin(){
  let admin = state.users.find(u => u.id === 'admin');
  if(!admin){
    admin = { id:'admin', nombre:'Administración UATPark', correo:'admin@uat.edu.mx', rol:'administrador' };
    state.users.push(admin);
  }
  if(!admin.hash) Object.assign(admin, credenciales(CLAVE_ADMIN_INICIAL));
}

// cada rol ve su propio menú
function ajustarNavPorRol(){
  const admin = esAdmin();
  $all('.nav-item').forEach(b=>{
    const r = b.dataset.roles;
    if(!r) return;
    b.hidden = (r === 'admin') ? !admin : admin;
  });
}

function cargarDatosDemo(){
  state = defaultState();
  asegurarAdmin();

  const now = Date.now(), MIN = 60000, HORA = 60*MIN, DIA = 24*HORA;
  const TODOS = ['Lun','Mar','Mié','Jue','Vie'];

  const valeria = { id:'20240001', nombre:'Valeria Gómez',   correo:'20240001@alumnos.uat.edu.mx',   rol:'estudiante', horarioEscolar:'Matutino', constanciaCargada:true };
  const carlos  = { id:'20240002', nombre:'Carlos Ramírez',  correo:'20240002@alumnos.uat.edu.mx',  rol:'estudiante', horarioEscolar:'Matutino', constanciaCargada:true };
  const daniela = { id:'20240003', nombre:'Daniela Ortiz',   correo:'20240003@alumnos.uat.edu.mx',   rol:'estudiante', horarioEscolar:'Matutino', constanciaCargada:true };
  const mariana = { id:'20240004', nombre:'Mariana Torres',  correo:'20240004@alumnos.uat.edu.mx',  rol:'estudiante', horarioEscolar:'Matutino', constanciaCargada:true };
  const roberto = { id:'E-1001',   nombre:'Roberto Salinas', correo:'roberto.salinas@docentes.uat.edu.mx', rol:'trabajador', horarioInicio:'08:00', horarioFin:'16:00' };
  [valeria, carlos, daniela, mariana, roberto].forEach(u => { Object.assign(u, credenciales(CLAVE_DEMO)); state.users.push(u); });

  // espacio asignado al trabajador (hileras 1 y 2)
  const sw = spotById('H1-01');
  sw.state = 'trabajador-ocupado'; sw.assignedWorkerId = roberto.id; roberto.workerSpotId = sw.id;

  // vehículos
  state.vehicles[valeria.id] = { sinVehiculo:false, marca:'Nissan Versa 2019',    placa:'TAM-1234', onapafa:false, licencia:'LIC-778812' };
  state.vehicles[carlos.id]  = { sinVehiculo:false, marca:'Honda Civic 2020',     placa:'TAM-5678', onapafa:false, licencia:'LIC-552201' };
  state.vehicles[roberto.id] = { sinVehiculo:false, marca:'Toyota Corolla 2018',  placa:'TAM-3321', onapafa:false, licencia:'LIC-310945' };
  state.vehicles[daniela.id] = { sinVehiculo:true, medio:'Transporte público', comentario:'' };
  state.vehicles[mariana.id] = { sinVehiculo:true, medio:'Transporte público', comentario:'' };

  // historial de reservas y accesos
  const hist = (u, spotId, status, haceMin) => state.reservations.push({
    id:uid('R'), userId:u.id, spotId, status, createdAt: now - haceMin*MIN, expiresAt: now - haceMin*MIN + 20*MIN
  });
  hist(valeria, 'H4-02', 'finalizada', 26*60);
  hist(valeria, 'H3-09', 'cancelada',  50*60);
  hist(valeria, 'H5-03', 'expirada',   75*60);
  hist(carlos,  'H3-12', 'finalizada', 30*60);

  // Carlos está estacionado ahora mismo
  const sc = spotById('H3-05');
  sc.state = 'ocupado'; sc.reservedBy = carlos.id;
  state.reservations.push({ id:uid('R'), userId:carlos.id, spotId:'H3-05', status:'estacionado', createdAt: now - 90*MIN, expiresAt: now - 70*MIN });

  state.accessLog.push(
    { type:'entrada', userId:valeria.id, spotId:'H4-02', time: now - 26*HORA },
    { type:'salida',  userId:valeria.id, spotId:'H4-02', time: now - 23*HORA },
    { type:'entrada', userId:carlos.id,  spotId:'H3-12', time: now - 30*HORA },
    { type:'salida',  userId:carlos.id,  spotId:'H3-12', time: now - 27*HORA },
    { type:'entrada', userId:carlos.id,  spotId:'H3-05', time: now - 85*MIN }
  );

  // reportes con el esquema de sanciones escalonado
  state.reports.push(
    { id:uid('REP'), placa:'TAM-9999', motivo:'Invade dos espacios', descripcion:'Estacionado sobre la línea, ocupa dos lugares.', time: now - 2*DIA, reporterId:valeria.id, conteo:1, sancion:'Advertencia', resuelto:true },
    { id:uid('REP'), placa:'TAM-9999', motivo:'Invade dos espacios', descripcion:'Otra vez ocupando dos cajones en la hilera 4.',  time: now - 1*DIA, reporterId:carlos.id,  conteo:2, sancion:'1 día de sanción' },
    { id:uid('REP'), placa:'TAM-4321', motivo:'Ocupa espacio de trabajadores sin ser trabajador', descripcion:'Vehículo sin autorización en la hilera 1.', time: now - 5*HORA, reporterId:daniela.id, conteo:1, sancion:'Advertencia' }
  );

  // rutas de aventón (cuentas reales del sistema: el flujo funciona de verdad)
  let k = 0;
  const ruta = (u, tipo, zona, horario, dias, asientos, punto, notas) => {
    const r = { id:uid('RIDE'), userId:u.id, activo:true, createdAt: now - (5 - k++)*HORA, nombre:u.nombre, rol:u.rol, correo:u.correo, tipo, zona, horario, dias, asientos, punto, notas };
    state.rides.push(r); return r;
  };
  const rCarlos  = ruta(carlos,  'ofrezco', 'Tamatán',  '07:00', TODOS, 3, 'Esquina del parque de la colonia', 'Salgo puntual y con aire acondicionado.');
  const rRoberto = ruta(roberto, 'ofrezco', 'Centro',   '07:30', TODOS, 2, 'Frente a la plaza principal', 'Voy directo a la facultad.');
  ruta(daniela, 'busco', 'Libertad', '07:15', ['Lun','Mié','Vie'], null, 'Esquina de la tienda de abarrotes', 'Entro a las 8:00.');
  ruta(mariana, 'busco', 'Centro',   '07:30', TODOS, null, 'Frente a la plaza principal', 'Busco aventón diario.');

  state.rideRequests.push(
    { id:uid('REQ'), rideId:rCarlos.id, fromUserId:daniela.id, toUserId:carlos.id, status:'pendiente', createdAt: now - 2*HORA,
      messages:[{ from:daniela.id, text:'Hola Carlos, vivo por Libertad y entro a las 8:00. ¿Te queda de camino?', time: now - 2*HORA }], ratings:{} },
    { id:uid('REQ'), rideId:rRoberto.id, fromUserId:mariana.id, toUserId:roberto.id, status:'aceptada', createdAt: now - 3*DIA,
      messages:[
        { from:mariana.id, text:'Hola, ¿me das aventón de lunes a viernes?', time: now - 3*DIA },
        { from:roberto.id, text:'Claro, paso por la plaza a las 7:30.', time: now - 3*DIA + 10*MIN }
      ],
      ratings:{ [mariana.id]:{ stars:5, comment:'Muy puntual y amable.', time: now - 1*DIA } } }
  );

  // notificaciones iniciales
  const nt = (u, text, type, haceMin) => state.notifications.push({ id:uid('N'), userId:u.id, text, type, time: now - haceMin*MIN, read:false });
  nt(valeria, 'Bienvenida a UATPark. Reserva tu lugar desde el mapa.', 'info', 120);
  nt(carlos,  'Daniela Ortiz te envió una solicitud de aventón.', 'info', 120);
  nt(carlos,  'Entrada registrada en el espacio H3-05.', 'ok', 85);
  nt(daniela, 'Enviaste una solicitud de aventón a Carlos Ramírez.', 'ok', 120);
  nt(roberto, 'Mariana Torres te calificó por el viaje compartido.', 'info', 1440);

  saveState();
}

function entrarDemo(rol){
  if(!MODO_DEMO) return;
  if(!state.users.some(u => u.id === DEMO_IDS.estudiante)) cargarDatosDemo();
  state.session = DEMO_IDS[rol];
  saveState();
  routeAfterAuth();
}

function wireDemo(){
  $all('[data-demo]').forEach(b => b.addEventListener('click', ()=> entrarDemo(b.dataset.demo)));
  $('#btnResetDemo').addEventListener('click', ()=>{
    if(!confirm('Se borrarán los datos actuales y se cargarán los de demostración. ¿Continuar?')) return;
    cargarDatosDemo();
    alert('Datos de demostración cargados. Ya puedes entrar con las cuentas de arriba.');
  });
}

function registrarServiceWorker(){
  if('serviceWorker' in navigator && location.protocol.startsWith('http')){
    navigator.serviceWorker.register('sw.js').catch(()=>{});
  }
}

function ocultarSplash(){
  const sp = document.getElementById('splash');
  if(!sp) return;
  setTimeout(()=>{
    sp.classList.add('hide');
    setTimeout(()=>sp.remove(), 600);
  }, 1300);
}

function init(){
  ocultarSplash();
  wireAuth();
  wireVehiculo();
  wireNav();
  wireReportes();
  wirePerfil();
  wireAdmin();
  wireHomeExtra();
  wireAventon();
  wireDemo();
  if(!MODO_DEMO) $('#demoBox').hidden = true;
  asegurarAdmin();
  saveState();
  registrarServiceWorker();

  if(state.session && currentUser()){
    if(esAdmin()){
      afterLoginUI();
      showView('admin');
    } else {
      afterLoginUI();
      const v = currentVehicle();
      showView(v ? 'home' : 'vehiculo');
      if(!v) beforeLoginUI();
    }
  } else {
    beforeLoginUI();
    showView('auth');
  }

  renderNotifBadge();

  // si otra pestaña cambia los datos (otra cuenta), nos actualizamos solos
  window.addEventListener('storage', e=>{
    if(e.key !== LS_KEY) return;
    state = loadState();
    renderNotifBadge();
    const act = document.querySelector('.view.active');
    if(act && !['view-auth','view-vehiculo'].includes(act.id)) renderView(act.id.replace('view-',''));
  });

  setInterval(()=>{
    checkExpiraciones();
    if(document.getElementById('view-home').classList.contains('active')) tickHomeTimer();
    const rt = document.getElementById('reservasTimer');
    if(rt){
      const res = activeReservation();
      if(res && res.status==='activa') rt.textContent = fmtClock(res.expiresAt - Date.now());
    }
  }, 1000);
}

document.addEventListener('DOMContentLoaded', init);
