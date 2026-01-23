package com.myproject.api.dtos;

public class ResetPasswordWithKeyDto {
    private String email;
    private String resetKey;
    private String newPassword;

    public ResetPasswordWithKeyDto() {}

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getResetKey() { return resetKey; }
    public void setResetKey(String resetKey) { this.resetKey = resetKey; }

    public String getNewPassword() { return newPassword; }
    public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
}
