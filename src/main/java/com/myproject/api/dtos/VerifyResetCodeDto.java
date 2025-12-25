package com.myproject.api.dtos;

public class VerifyResetCodeDto {
    private String email;
    private String token;

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }
}
