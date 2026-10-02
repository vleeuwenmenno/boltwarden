// This presentation fixture never submits, stores, or verifies credentials.
document.querySelector('form').addEventListener('submit', event => {
  event.preventDefault();
  document.querySelector('#status').textContent = 'Demo complete. No sign-in request was sent.';
});
