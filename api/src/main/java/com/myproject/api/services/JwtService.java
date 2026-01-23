package com.myproject.api.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import com.myproject.api.entities.User;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;
import java.nio.charset.StandardCharsets; // (IMPORT MỚI)

@Service
public class JwtService {

    // 1. CHỮ KÝ BÍ MẬT (Giữ nguyên)
    private static final String SECRET_KEY = "daylachuoibimatratdainammuoikytudebao đảmantoanvakhongbicrackdaylachuoibimatratdainammuoikytudebaođamantoanvakhongbicrack";

    // 2. Tạo "Vé" (Token) (Giữ nguyên)
    public String generateToken(User user) {
        long expirationTime = 1000 * 60 * 60 * 24; // 1 ngày

        return Jwts.builder()
                .subject(user.getEmail()) 
                .issuedAt(new Date(System.currentTimeMillis())) 
                .expiration(new Date(System.currentTimeMillis() + expirationTime)) 
                .signWith(getSigningKey()) 
                .compact(); 
    }

    // 3. Lấy "Chìa khóa" (Key) từ Chữ ký bí mật
    private SecretKey getSigningKey() {
        // (SỬA LẠI DÒNG NÀY)
        // Lấy byte từ chuỗi UTF-8, thay vì giải mã Base64
        byte[] keyBytes = SECRET_KEY.getBytes(StandardCharsets.UTF_8); 
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // --- Các hàm bên dưới dùng để "Đọc Vé" (Giải mã) ---
    // (Giữ nguyên)

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public boolean isTokenValid(String token, User user) {
        final String username = extractUsername(token);
        return (username.equals(user.getEmail()) && !isTokenExpired(token));
    }
}