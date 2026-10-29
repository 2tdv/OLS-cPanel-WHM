// Optional enhancements: copy buttons on code blocks and a screenshot lightbox. The site works without this file.
(function () {
  'use strict';
  document.querySelectorAll('.codeblock').forEach(function (block) {
    var pre = block.querySelector('pre');
    if (!pre || !navigator.clipboard) return;
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy';
    button.textContent = 'Copy';
    button.setAttribute('aria-label', 'Copy the command to the clipboard');
    button.addEventListener('click', function () {
      navigator.clipboard.writeText(pre.innerText.replace(/\n$/, '')).then(function () {
        button.textContent = 'Copied';
      }, function () {
        button.textContent = 'Copy failed';
      }).then(function () {
        setTimeout(function () { button.textContent = 'Copy'; }, 2000);
      });
    });
    block.appendChild(button);
  });

  if (typeof HTMLDialogElement !== 'function') return;
  var dialog = document.createElement('dialog');
  dialog.className = 'lightbox';
  dialog.setAttribute('aria-label', 'Screenshot');
  var close = document.createElement('button');
  close.type = 'button';
  close.textContent = 'Close';
  var big = document.createElement('img');
  big.alt = '';
  dialog.appendChild(close);
  dialog.appendChild(big);
  document.body.appendChild(dialog);
  close.addEventListener('click', function () { dialog.close(); });
  dialog.addEventListener('click', function (event) { if (event.target === dialog) dialog.close(); });
  document.querySelectorAll('figure.shot a').forEach(function (link) {
    link.addEventListener('click', function (event) {
      event.preventDefault();
      var img = link.querySelector('img');
      big.src = link.getAttribute('href');
      big.alt = img ? img.alt : '';
      dialog.showModal();
      close.focus();
    });
  });
})();
