document.addEventListener('DOMContentLoaded', function() {
            
    const loginForm = document.getElementById('loginForm');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const submitButton = document.getElementById('submitButton');
    const errorMessage = document.getElementById('errorMessage');
    const successMessage = document.getElementById('successMessage');

    function validateForm() {
        const isEmailFilled = emailInput.value.trim() !== '';
        const isPasswordFilled = passwordInput.value.trim() !== '';

        if (isEmailFilled && isPasswordFilled) {
            submitButton.disabled = false;
        } else {
            submitButton.disabled = true;
        }
    }

    emailInput.addEventListener('input', validateForm);
    passwordInput.addEventListener('input', validateForm);

    loginForm.addEventListener('submit', function(event) {
        event.preventDefault(); 

        errorMessage.style.display = 'none';
        successMessage.style.display = 'none';

        const email = emailInput.value.trim();
        const password = passwordInput.value.trim();

        const MOCK_USER_EMAIL = 'test@gmail.com';
        const MOCK_USER_PASS = '123456';

        if (email === MOCK_USER_EMAIL && password === MOCK_USER_PASS) {
            successMessage.textContent = 'Đăng nhập thành công! Đang chuyển bạn đến trang chủ...';
            successMessage.style.display = 'block';
            submitButton.disabled = true;

            setTimeout(function() {
                window.location.href = 'index.html'; 
            }, 2000);

        } else {
            errorMessage.textContent = 'Email hoặc mật khẩu không đúng. Vui lòng thử lại.';
            errorMessage.style.display = 'block';
        }
    });
});