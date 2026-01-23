package com.myproject.api.controllers;

import com.myproject.api.dtos.*;
import com.myproject.api.entities.User;
import com.myproject.api.repositories.UserRepository;
import com.myproject.api.services.PasswordResetService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final PasswordResetService passwordResetService;

    public AuthController(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            PasswordResetService passwordResetService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.passwordResetService = passwordResetService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegisterDto registerRequest) {

        if (registerRequest == null
                || isBlank(registerRequest.getUsername())
                || isBlank(registerRequest.getEmail())
                || isBlank(registerRequest.getPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("username, email, password are required."));
        }

        String email = normalizeEmail(registerRequest.getEmail());

        if (userRepository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new MessageResponse("Email already exists. Please login."));
        }

        User user = new User();
        user.setUsername(registerRequest.getUsername().trim());
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(registerRequest.getPassword().trim()));
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginDto loginRequest) {

        if (loginRequest == null
                || isBlank(loginRequest.getEmail())
                || isBlank(loginRequest.getPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("email and password are required."));
        }

        String email = normalizeEmail(loginRequest.getEmail());
        String password = loginRequest.getPassword().trim();

        try {
            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email, password)
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String fakeToken = "your_fake_jwt_token_for_" + email;
            return ResponseEntity.ok(new LoginResponse("User logged in successfully!", fakeToken));

        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid credentials. Please try again."));
        }
    }

    /**
     * Forgot password:
     * - Check email tồn tại trong database
     * - Nếu tồn tại -> tạo token + gửi email
     * - Nếu không -> return error
     */
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordDto request) {
        String emailRaw = (request == null) ? null : request.getEmail();
        if (isBlank(emailRaw)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is required."));
        }

        String email = normalizeEmail(emailRaw);

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Email not found. Please check your email or register."));
        }

        passwordResetService.issueTokenAndSendEmail(email);

        return ResponseEntity.ok(new MessageResponse(
                "A reset code has been sent to your email."
        ));
    }

    /**
     * Verify code:
     * - Client nhập email + token (6 số) -> nếu đúng trả về resetKey (để qua reset-password.html)
     */
    @PostMapping("/verify-reset-code")
    public ResponseEntity<?> verifyResetCode(@RequestBody VerifyResetCodeDto request) {
        if (request == null || isBlank(request.getEmail()) || isBlank(request.getToken())) {
            return ResponseEntity.badRequest().body(new MessageResponse("email and token are required."));
        }

        String email = normalizeEmail(request.getEmail());
        String token = request.getToken().trim();

        System.out.println("[DEBUG] Verify request: email=" + email + ", token=" + token);

        // bảo mật: vẫn nên check user tồn tại
        if (userRepository.findByEmail(email).isEmpty()) {
            System.out.println("[DEBUG] User not found!");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Invalid reset request."));
        }

        String resetKey = passwordResetService.verifyCodeAndIssueResetKey(email, token);
        System.out.println("[DEBUG] Reset key result: " + resetKey);
        if (resetKey == null) {
            System.out.println("[DEBUG] Reset key is null!");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Invalid token or token expired."));
        }

        return ResponseEntity.ok(new VerifyCodeResponse("Code verified.", resetKey));
    }

    /**
     * Reset password:
     * - reset-password.html KHÔNG nhập token nữa
     * - nó sẽ gửi email + resetKey + newPassword
     */
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordDto request) {

        if (request == null
                || isBlank(request.getEmail())
                || isBlank(request.getResetKey())
                || isBlank(request.getNewPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("email, resetKey, newPassword are required."));
        }

        String email = normalizeEmail(request.getEmail());
        String resetKey = request.getResetKey().trim();
        String newPassword = request.getNewPassword().trim();

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid reset request."));
        }

        if (!passwordResetService.verifyResetKey(email, resetKey)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse("Invalid reset session or session expired. Please verify code again."));
        }

        User user = userOpt.get();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetService.consumeAll(email);

        return ResponseEntity.ok(new MessageResponse("Password reset successfully!"));
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    @GetMapping("/debug/clear-tokens")
    public ResponseEntity<?> clearTokens() {
        passwordResetService.clearAllTokens();
        return ResponseEntity.ok(new MessageResponse("All password reset tokens cleared."));
    }

    // ========= RESPONSES =========

    public static class MessageResponse {
        private final String message;
        public MessageResponse(String message) { this.message = message; }
        public String getMessage() { return message; }
    }

    public static class LoginResponse {
        private final String message;
        private final String token;
        public LoginResponse(String message, String token) {
            this.message = message;
            this.token = token;
        }
        public String getMessage() { return message; }
        public String getToken() { return token; }
    }

    public static class VerifyCodeResponse {
        private final String message;
        private final String resetKey;
        public VerifyCodeResponse(String message, String resetKey) {
            this.message = message;
            this.resetKey = resetKey;
        }
        public String getMessage() { return message; }
        public String getResetKey() { return resetKey; }
    }
}
