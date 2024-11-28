package com.cnf.ultils;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String errorMessage;
        if (exception.getMessage().contains("User account is disabled")) {
            errorMessage = "Tài khoản của bạn đã bị cấm.";
        } else if (exception.getMessage().contains("Bad credentials")) {
            errorMessage = "Tên đăng nhập hoặc mật khẩu không hợp lệ.";
        } else {
            errorMessage = "Đăng nhập thất bại.";
        }
        request.getSession().setAttribute("errorMessage", errorMessage);
        response.sendRedirect("/login?error");
//        String errorMessage;
//        if (exception.getMessage().contains("User account is disabled")) {
//            errorMessage = "Your account has been disabled.";
//        } else if (exception.getMessage().contains("Bad credentials")) {
//            errorMessage = "Invalid username or password.";
//        } else if (exception.getMessage().contains("OAuth2AuthenticationException")) {
//            errorMessage = "Failed to authenticate with OAuth2 provider.";
//        } else {
//            errorMessage = "Login failed.";
//        }
//        request.getSession().setAttribute("errorMessage", errorMessage);
//        response.sendRedirect("/login?error");
    }
}
