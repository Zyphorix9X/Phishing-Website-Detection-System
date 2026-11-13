document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('profile-form');
    if (!form) return;
    const email = form.elements.email;
    const password = form.elements.new_password;
    const confirmation = form.elements.confirm_password;
    const current = form.elements.current_password;
    const match = document.getElementById('password-match');

    const updateValidation = () => {
        const value = password.value;
        const rules = {
            length: value.length >= 12 && value.length <= 256,
            upper: /\p{Lu}/u.test(value),
            lower: /\p{Ll}/u.test(value),
            number: /\p{N}/u.test(value),
            symbol: /[^\p{L}\p{N}\s]/u.test(value)
        };
        form.querySelectorAll('[data-password-rule]').forEach((item) => {
            item.classList.toggle('requirement-met', rules[item.dataset.passwordRule]);
        });
        password.setCustomValidity(value && !Object.values(rules).every(Boolean)
            ? 'Use 12–256 characters with uppercase and lowercase letters, a number, and a symbol.' : '');
        confirmation.required = Boolean(value);
        const mismatch = confirmation.value && confirmation.value !== value;
        confirmation.setCustomValidity(mismatch ? 'The new passwords must match.' : '');
        match.textContent = confirmation.value ? (mismatch ? 'The passwords do not match yet.' : 'The passwords match.') : '';
        match.classList.toggle('is-mismatch', Boolean(mismatch));
        current.required = Boolean(value) || email.value.trim().toLowerCase() !== form.dataset.originalEmail.toLowerCase();
    };
    [email, password, confirmation].forEach((input) => input.addEventListener('input', updateValidation));
    form.addEventListener('submit', updateValidation);
    updateValidation();
});
