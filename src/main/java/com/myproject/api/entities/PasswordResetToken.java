package com.myproject.api.entities;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "password_reset_tokens")
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 256)
    private String email;

    @Column(name = "token_hash", nullable = false)
    private String tokenHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private int attempts = 0;

    @Column(name = "reset_key", length = 64)
    private String resetKey;

    @Column(name = "reset_key_expires_at")
    private Instant resetKeyExpiresAt;

    // ===== getters/setters =====

    public Long getId() { return id; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getTokenHash() { return tokenHash; }
    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }

    public int getAttempts() { return attempts; }
    public void setAttempts(int attempts) { this.attempts = attempts; }

    public String getResetKey() { return resetKey; }
    public void setResetKey(String resetKey) { this.resetKey = resetKey; }

    public Instant getResetKeyExpiresAt() { return resetKeyExpiresAt; }
    public void setResetKeyExpiresAt(Instant resetKeyExpiresAt) { this.resetKeyExpiresAt = resetKeyExpiresAt; }
}
