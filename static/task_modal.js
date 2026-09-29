(() => {
  const dialog = document.getElementById('task-dialog');
  if (!dialog || !dialog.showModal) return;
  const headers = {'X-Requested-With': 'XMLHttpRequest'};

  document.addEventListener('click', async event => {
    const link = event.target.closest('[data-task-modal]');
    if (!link) return;
    event.preventDefault();
    try {
      const response = await fetch(link.href, {headers});
      if (!response.ok) throw new Error('Could not load task form');
      dialog.innerHTML = await response.text();
      dialog.showModal();
      dialog.querySelector('input:not([type="hidden"]), select, textarea')?.focus();
    } catch {
      window.location.assign(link.href);
    }
  });

  dialog.addEventListener('click', event => {
    if (event.target === dialog || event.target.closest('[data-dialog-close]')) dialog.close();
  });

  dialog.addEventListener('submit', async event => {
    const form = event.target.closest('[data-task-form]');
    if (!form) return;
    event.preventDefault();
    const submit = form.querySelector('button[type="submit"]');
    if (submit) submit.disabled = true;
    try {
      const response = await fetch(form.action, {method: 'POST', headers,
        body: new FormData(form), credentials: 'same-origin'});
      if (response.redirected && response.url.includes('/login')) {
        window.location.assign(response.url);
        return;
      }
      if (response.headers.get('content-type')?.includes('application/json')) {
        const saved = await response.json();
        window.location.assign(saved.redirect);
        return;
      }
      if (response.status === 422) {
        dialog.innerHTML = await response.text();
        dialog.scrollTop = 0;
        dialog.querySelector('[role="alert"]')?.focus();
        return;
      }
      throw new Error('Could not save task');
    } catch {
      if (submit) submit.disabled = false;
      window.alert('保存失败，请重试。');
    }
  });
})();
