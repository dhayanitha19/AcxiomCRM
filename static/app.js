document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('form.needs-validation').forEach((form) => {
    form.addEventListener('submit', (event) => {
      const password = form.querySelector('[name="password"]');
      const confirmation = form.querySelector('[name="confirm_password"]');
      if (password && confirmation) {
        confirmation.setCustomValidity(password.value === confirmation.value ? '' : 'Passwords do not match.');
      }
      if (!form.checkValidity()) {
        event.preventDefault();
        event.stopPropagation();
      }
      form.classList.add('was-validated');
    });
  });
  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm || 'Continue with this action?')) event.preventDefault();
    });
  });
});
