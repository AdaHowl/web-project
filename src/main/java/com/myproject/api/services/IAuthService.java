package com.myproject.api.services;

import com.myproject.api.dtos.LoginDto; // Thêm import này
import com.myproject.api.dtos.RegisterDto;
import com.myproject.api.entities.User;

// Đây là "Menu" (Interface) định nghĩa các chức năng
public interface IAuthService {
    
    // Chức năng: Đăng ký
    User register(RegisterDto registerDto);

    // (THÊM MỚI) Chức năng: Đăng nhập
    // Nhận vào Dto, trả về "Tấm vé" (String)
    String login(LoginDto loginDto);
}