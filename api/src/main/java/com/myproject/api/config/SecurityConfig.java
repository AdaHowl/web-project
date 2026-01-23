package com.myproject.api.config;

import com.myproject.api.repositories.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Collections;

@Configuration 
@EnableWebSecurity 
public class SecurityConfig {

    private final UserRepository userRepository;

    public SecurityConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // 1. BEAN: MÃ HÓA MẬT KHẨU (PasswordEncoder) - FIX LỖI THIẾU BEAN
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 2. BEAN: Lấy thông tin User từ Database (Sử dụng email làm username)
    @Bean
    public UserDetailsService userDetailsService() {
        // Đảm bảo UserRepository có findByEmail(email) (như đã sửa)
        return email -> userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    // 3. BEAN: Cung cấp phương thức xác thực
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder()); // Sử dụng PasswordEncoder đã tạo
        return authProvider;
    }

    // 4. BEAN: Quản lý xác thực (Authentication Manager)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // 5. Cấu hình "Người bảo vệ" (Security Filter Chain)
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Cấu hình CORS
            .cors(cors -> {
                var source = new UrlBasedCorsConfigurationSource();
                var corsConfig = new CorsConfiguration();
                // Cho phép Frontend (Port 5500) truy cập
                corsConfig.setAllowedOrigins(Arrays.asList("http://127.0.0.1:5500", "http://localhost:5500")); 
                corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                corsConfig.setAllowedHeaders(Collections.singletonList("*"));
                corsConfig.setAllowCredentials(true);
                source.registerCorsConfiguration("/**", corsConfig);
                cors.configurationSource(source);
            })
            .csrf(csrf -> csrf.disable()) // Tắt CSRF
            .authorizeHttpRequests(auth -> auth
                // Cho phép preflight CORS
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Mở public các API đăng ký/đăng nhập
                .requestMatchers("/api/auth/register",
                                 "/api/auth/login",
                                 "/api/auth/forgot-password",
                                 "/api/auth/verify-reset-code",
                                 "/api/auth/reset-password").permitAll()
                // Mọi đường dẫn KHÁC đều phải được "xác thực"
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authenticationProvider(authenticationProvider());

        return http.build();
    }
}