/**
 * ESPE U9 — Feedback Widget (Bug / Idée)
 * Bouton flottant + modal — s'injecte automatiquement au chargement.
 */
(function () {
  var CSS = '\
.fb-fab{position:fixed;bottom:24px;right:24px;z-index:9000;display:flex;flex-direction:column;align-items:flex-end;gap:8px;pointer-events:none}\
.fb-fab>*{pointer-events:auto}\
.fb-fab-btn{width:54px;height:54px;border-radius:50%;border:none;background:linear-gradient(135deg,#1a6b2e 0%,#228b38 100%);color:#fff;cursor:pointer;box-shadow:0 4px 16px rgba(26,107,46,0.35);display:flex;align-items:center;justify-content:center;transition:transform .2s,box-shadow .2s}\
.fb-fab-btn:hover{transform:scale(1.08);box-shadow:0 6px 24px rgba(26,107,46,0.45)}\
.fb-fab-btn svg{width:26px;height:26px}\
.fb-overlay{position:fixed;inset:0;z-index:9500;background:rgba(0,0,0,0.45);display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity .25s;pointer-events:none}\
.fb-overlay.open{opacity:1;pointer-events:auto}\
.fb-modal{background:#fff;border-radius:20px;box-shadow:0 12px 48px rgba(0,0,0,0.18);width:92vw;max-width:440px;max-height:90vh;overflow-y:auto;transform:translateY(30px) scale(0.95);transition:transform .3s ease;font-family:"Outfit",sans-serif}\
.fb-overlay.open .fb-modal{transform:translateY(0) scale(1)}\
.fb-modal-head{background:linear-gradient(135deg,#0f3d1a 0%,#1a6b2e 100%);color:#fff;padding:20px 24px 16px;border-radius:20px 20px 0 0;display:flex;align-items:center;justify-content:space-between}\
.fb-modal-title{font-family:"Bebas Neue",sans-serif;font-size:1.35rem;letter-spacing:2px}\
.fb-modal-close{background:rgba(255,255,255,0.15);border:none;color:#fff;width:32px;height:32px;border-radius:50%;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;transition:background .2s}\
.fb-modal-close:hover{background:rgba(255,255,255,0.3)}\
.fb-modal-body{padding:20px 24px 24px}\
.fb-types{display:flex;gap:8px;margin-bottom:16px}\
.fb-type{flex:1;padding:10px 6px;border:2px solid #e0e2e8;border-radius:12px;background:#fff;cursor:pointer;text-align:center;font-size:13px;font-weight:600;font-family:inherit;color:#6b7280;transition:all .2s}\
.fb-type:hover{border-color:#1a6b2e;color:#1a6b2e}\
.fb-type.active{border-color:#1a6b2e;background:#e8f5e9;color:#1a6b2e}\
.fb-type-icon{display:block;font-size:22px;margin-bottom:4px}\
.fb-field{margin-bottom:14px}\
.fb-label{display:block;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#6b7280;margin-bottom:6px}\
.fb-textarea{width:100%;min-height:110px;padding:12px 16px;border:2px solid #e0e2e8;border-radius:14px;font-family:inherit;font-size:14px;line-height:1.5;resize:vertical;color:#1a1d25;transition:border-color .2s,box-shadow .2s;background:#fafafa}\
.fb-textarea:focus{outline:none;border-color:#1a6b2e;box-shadow:0 0 0 3px rgba(26,107,46,0.1);background:#fff}\
.fb-textarea::placeholder{color:#9ca3af}\
.fb-submit{width:100%;padding:14px;border:none;border-radius:14px;background:linear-gradient(135deg,#1a6b2e 0%,#228b38 100%);color:#fff;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer;transition:opacity .2s,transform .1s;letter-spacing:.5px}\
.fb-submit:hover{opacity:.92}\
.fb-submit:active{transform:scale(.98)}\
.fb-submit:disabled{opacity:.5;cursor:not-allowed}\
.fb-success{text-align:center;padding:32px 16px}\
.fb-success-icon{font-size:48px;margin-bottom:12px}\
.fb-success-msg{font-size:16px;font-weight:600;color:#1a6b2e;margin-bottom:6px}\
.fb-success-sub{font-size:13px;color:#6b7280}\
.fb-error{background:rgba(220,38,38,0.08);border:1px solid #dc2626;color:#dc2626;padding:8px 14px;border-radius:10px;font-size:13px;margin-bottom:12px}\
@media(max-width:600px){\
.fb-fab{bottom:16px;right:16px}\
.fb-fab-btn{width:48px;height:48px}\
.fb-fab-btn svg{width:22px;height:22px}\
body.has-chat-form .fb-fab{bottom:90px}\
.fb-overlay{align-items:flex-end}\
.fb-modal{width:100vw;max-width:100%;border-radius:20px 20px 0 0;max-height:85vh}\
.fb-modal-head{border-radius:20px 20px 0 0;padding:16px 18px 12px}\
.fb-modal-body{padding:16px 18px 20px}\
.fb-type{padding:12px 6px;font-size:14px}\
.fb-type-icon{font-size:24px}\
.fb-textarea{min-height:100px;font-size:16px}\
.fb-submit{padding:16px;font-size:16px}\
}';

  var style = document.createElement('style');
  style.textContent = CSS;
  document.head.appendChild(style);

  var fab = document.createElement('div');
  fab.className = 'fb-fab';
  fab.innerHTML = '<button class="fb-fab-btn" title="Signaler un bug ou proposer une idée" aria-label="Feedback">'
    + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
    + '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>'
    + '<line x1="9" y1="9" x2="15" y2="9"/><line x1="12" y1="9" x2="12" y2="13"/>'
    + '</svg></button>';
  document.body.appendChild(fab);

  var overlay = document.createElement('div');
  overlay.className = 'fb-overlay';
  overlay.innerHTML = '<div class="fb-modal">'
    + '<div class="fb-modal-head">'
    + '  <span class="fb-modal-title">💡 Feedback</span>'
    + '  <button class="fb-modal-close" aria-label="Fermer">&times;</button>'
    + '</div>'
    + '<div class="fb-modal-body">'
    + '  <div class="fb-types">'
    + '    <button class="fb-type active" data-type="bug"><span class="fb-type-icon">🐛</span>Bug</button>'
    + '    <button class="fb-type" data-type="idee"><span class="fb-type-icon">💡</span>Idée</button>'
    + '    <button class="fb-type" data-type="autre"><span class="fb-type-icon">📝</span>Autre</button>'
    + '  </div>'
    + '  <div id="fbErr"></div>'
    + '  <div class="fb-field">'
    + '    <label class="fb-label">Ton message</label>'
    + '    <textarea class="fb-textarea" id="fbMsg" placeholder="Décris le bug rencontré, ton idée d\'amélioration ou ta suggestion…"></textarea>'
    + '  </div>'
    + '  <button class="fb-submit" id="fbSend">Envoyer</button>'
    + '</div>'
    + '</div>';
  document.body.appendChild(overlay);

  var modal = overlay.querySelector('.fb-modal');
  var closeBtn = overlay.querySelector('.fb-modal-close');
  var typeBtns = overlay.querySelectorAll('.fb-type');
  var msgInput = document.getElementById('fbMsg');
  var sendBtn = document.getElementById('fbSend');
  var errBox = document.getElementById('fbErr');
  var currentType = 'bug';

  function open() { overlay.classList.add('open'); msgInput.focus(); }
  function close() { overlay.classList.remove('open'); }
  function resetForm() {
    currentType = 'bug';
    typeBtns.forEach(function (b) { b.classList.toggle('active', b.dataset.type === 'bug'); });
    msgInput.value = '';
    errBox.innerHTML = '';
    sendBtn.disabled = false;
    var body = overlay.querySelector('.fb-modal-body');
    var succ = body.querySelector('.fb-success');
    if (succ) { succ.remove(); body.querySelector('.fb-types').style.display = ''; body.querySelector('.fb-field').style.display = ''; sendBtn.style.display = ''; }
  }

  fab.querySelector('.fb-fab-btn').addEventListener('click', function () { resetForm(); open(); });
  closeBtn.addEventListener('click', close);
  overlay.addEventListener('click', function (ev) { if (ev.target === overlay) close(); });

  typeBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      typeBtns.forEach(function (b) { b.classList.remove('active'); });
      btn.classList.add('active');
      currentType = btn.dataset.type;
    });
  });

  sendBtn.addEventListener('click', function () {
    var msg = msgInput.value.trim();
    if (!msg) { errBox.innerHTML = '<div class="fb-error">Écris un message avant d\'envoyer.</div>'; return; }
    errBox.innerHTML = '';
    sendBtn.disabled = true;
    sendBtn.textContent = 'Envoi…';

    fetch('api.php?action=send_feedback', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: currentType, message: msg, page: window.location.pathname + window.location.hash })
    })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (d.success) {
          var body = overlay.querySelector('.fb-modal-body');
          body.querySelector('.fb-types').style.display = 'none';
          body.querySelector('.fb-field').style.display = 'none';
          sendBtn.style.display = 'none';
          errBox.innerHTML = '';
          var succ = document.createElement('div');
          succ.className = 'fb-success';
          succ.innerHTML = '<div class="fb-success-icon">✅</div>'
            + '<div class="fb-success-msg">Merci pour ton retour !</div>'
            + '<div class="fb-success-sub">Ton message a bien été envoyé au coach.</div>';
          body.appendChild(succ);
          setTimeout(close, 2500);
        } else {
          errBox.innerHTML = '<div class="fb-error">' + (d.error || 'Erreur inconnue') + '</div>';
          sendBtn.disabled = false;
          sendBtn.textContent = 'Envoyer';
        }
      })
      .catch(function () {
        errBox.innerHTML = '<div class="fb-error">Erreur réseau, réessaie.</div>';
        sendBtn.disabled = false;
        sendBtn.textContent = 'Envoyer';
      });
  });

  document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && overlay.classList.contains('open')) close(); });
})();
