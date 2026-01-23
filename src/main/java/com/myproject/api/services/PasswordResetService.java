package com.myproject.api.services;

import com.myproject.api.entities.PasswordResetToken;
import com.myproject.api.repositories.PasswordResetTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.logging.Logger;

@Service
public class PasswordResetService {

    private final JavaMailSender mailSender;
    private final PasswordResetTokenRepository tokenRepo;
    private final SecureRandom random = new SecureRandom();
    private static final Logger logger = Logger.getLogger(PasswordResetService.class.getName());

    // 10 phút
    private static final long TOKEN_TTL_SECONDS = 60 * 60; // 1 hour for testing
    private static final long RESET_KEY_TTL_SECONDS = 60 * 60;
    private static final String PEPPER = "your-secret-pepper-key-12345";

    @Value("${app.mail.from:no-reply@myproject.local}")
    private String fromEmail;

    public PasswordResetService(JavaMailSender mailSender, PasswordResetTokenRepository tokenRepo) {
        this.mailSender = mailSender;
        this.tokenRepo = tokenRepo;
    }

    public void issueTokenAndSendEmail(String emailRaw) {
        String email = normalize(emailRaw);

        logger.info("Issuing password reset token for email: " + email);

        String token = "%06d".formatted(random.nextInt(1_000_000));

        PasswordResetToken prt = new PasswordResetToken();
        prt.setEmail(email);
        prt.setTokenHash(sha256(email + ":" + token + ":" + PEPPER));
        prt.setCreatedAt(Instant.now());
        prt.setExpiresAt(Instant.now().plusSeconds(TOKEN_TTL_SECONDS));
        prt.setAttempts(0);
        prt.setResetKey(null);
        prt.setResetKeyExpiresAt(null);

        tokenRepo.save(prt);

        logger.info("Token saved, sending email to: " + email + " with token: " + token);

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setFrom(fromEmail);
        msg.setTo(email);
        msg.setSubject("Password Reset Code");
        msg.setText(
                "Your password reset code is: " + token + "\n\n" +
                "This code will expire in 10 minutes."
        );
        try {
            mailSender.send(msg);
            logger.info("Email sent successfully to: " + email);
        } catch (Exception e) {
            logger.severe("Failed to send email to: " + email + " Error: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Verify code 6 số -> nếu đúng, tạo resetKey (UUID) cho bước reset-password (không cần nhập token nữa)
     */
    public String verifyCodeAndIssueResetKey(String emailRaw, String tokenRaw) {
        String email = normalize(emailRaw);
        String token = tokenRaw == null ? "" : tokenRaw.trim();

        logger.info("=== VERIFY CODE === Email: " + email + ", Token: " + token);

        var opt = tokenRepo.findTopByEmailOrderByCreatedAtDesc(email);
        if (opt.isEmpty()) {
            logger.warning("Token not found for email: " + email);
            return null;
        }

        PasswordResetToken prt = opt.get();

        logger.info("Found token, expiresAt: " + prt.getExpiresAt() + ", now: " + Instant.now());
        
        if (Instant.now().isAfter(prt.getExpiresAt())) {
            logger.warning("Token expired!");
            return null;
        }

        if (prt.getAttempts() >= 10) {
            logger.warning("Too many attempts!");
            return null;
        }

        String hash = sha256(email + ":" + token + ":" + PEPPER);
        logger.info("Calculated hash: " + hash);
        logger.info("Stored hash: " + prt.getTokenHash());
        
        if (!hash.equals(prt.getTokenHash())) {
            logger.warning("Hash mismatch!");
            prt.setAttempts(prt.getAttempts() + 1);
            tokenRepo.save(prt);
            return null;
        }

        String resetKey = UUID.randomUUID().toString().replace("-", "");
        prt.setResetKey(resetKey);
        prt.setResetKeyExpiresAt(Instant.now().plusSeconds(RESET_KEY_TTL_SECONDS));
        tokenRepo.save(prt);

        logger.info("Code verified successfully, resetKey issued: " + resetKey);
        return resetKey;
    }

    public boolean verifyResetKey(String emailRaw, String resetKeyRaw) {
        String email = normalize(emailRaw);
        String resetKey = resetKeyRaw == null ? "" : resetKeyRaw.trim();

        var opt = tokenRepo.findTopByEmailOrderByCreatedAtDesc(email);
        if (opt.isEmpty()) return false;

        PasswordResetToken prt = opt.get();
        if (prt.getResetKey() == null) return false;
        if (!prt.getResetKey().equals(resetKey)) return false;
        if (prt.getResetKeyExpiresAt() == null) return false;
        return !Instant.now().isAfter(prt.getResetKeyExpiresAt());
    }

    public void consumeAll(String emailRaw) {
        tokenRepo.deleteByEmail(normalize(emailRaw));
    }

    public void clearAllTokens() {
        tokenRepo.deleteAll();
    }

    private String normalize(String email) {
        return email.trim().toLowerCase();
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 error", e);
        }
    }
}
