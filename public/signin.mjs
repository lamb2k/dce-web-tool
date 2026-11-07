const form = document.querySelector('#signin');
const status = document.querySelector('#status');
form.addEventListener('submit', async event => {
  event.preventDefault();
  const button = form.querySelector('button'); button.disabled = true; status.textContent = '';
  const username = form.elements.username.value, password = form.elements.password.value;
  try {
    const response = await fetch('/signin', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({username,password}) });
    form.elements.password.value = '';
    if (response.ok) location.replace('/');
    else status.textContent = response.status === 401 ? 'Username or password not recognised.' : 'Sign-in unavailable. Try again.';
  } catch { status.textContent = 'Connection interrupted. Try again.'; }
  finally { button.disabled = false; }
});
