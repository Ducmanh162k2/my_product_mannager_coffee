package com.cnf.services;


import com.cnf.entity.PasswordResetToken;
import com.cnf.entity.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class EmailSenderService {
    @Autowired
    private JavaMailSender mailSender;
    @Autowired
    private PasswordResetTokenService verificationTokenService;
    @Autowired
    private UserService userService;

    public void sendEmail(String toEmail, String subject, String body) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setFrom("ducmanh16022002@gmail.com", "CHILL AND FREE COFFEE");
        helper.setTo(toEmail);
        helper.setSubject(subject);
        body += "<hr><img src ='cid:logoImage' />";
        helper.setText(body, true);
        ClassPathResource resource = new ClassPathResource("/static/client_assets/img/logo.png");
        helper.addInline("logoImage", resource) ;
        mailSender.send(message);
    }
    public void sendEmailContact(String fromEmail, String subject, String body) throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true);
        helper.setFrom(fromEmail);
        helper.setTo("ducmanh16022002@gmail.com");
        helper.setSubject(subject);
        body += "<hr><img src ='cid:logoImage' />";
        helper.setText(body, true);
        ClassPathResource resource = new ClassPathResource("/static/client_assets/img/logo.png");
        helper.addInline("logoImage", resource) ;
        mailSender.send(message);
    }

    public void sendVerificationEmail(User user) throws MessagingException {
        String token = createVerificationToken(user).getToken();
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom("ducmanh16022002@gmail.com");
        helper.setTo(user.getEmail());
        helper.setSubject(user.getFull_name() + ", Email xác thực của Chill and Free Coffee.");

        String mailContent =
                "<html>" +
                        "<body style='font-family: Arial, sans-serif; color: #333;'>" +
                        "   <div style='max-width: 600px; margin: 20px auto; border: 1px solid #ddd; padding: 20px; background-color: #f0f8f7;'>" +
                        "       <h2 style='color: #2e8b57; text-align: center;'>Xác thực thành viên Seed</h2>" +
                        "       <p style='font-size: 16px; text-align: center;'>" +
                        "           Xin chào, <strong>" + user.getFull_name() + "</strong>! Chào mừng bạn đến với Seed.<br>" +
                        "           Vui lòng nhấn vào nút dưới đây để kích hoạt tài khoản của bạn." +
                        "       </p>" +
                        "       <div style='text-align: center; margin: 40px 0;'>" +
                        "           <a href='http://localhost:8080/verify/result?token=" + token + "'" +
                        "              style='display: inline-block; background-color: #2e8b57; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>" +
                        "               Kích hoạt tài khoản" +
                        "           </a>" +
                        "       </div>" +
                        "       <p style='font-size: 14px; color: #666;'>" +
                        "           Nếu nút trên không hoạt động, hãy sao chép và dán liên kết dưới đây vào trình duyệt của bạn:<br>" +
                        "           <a href='http://localhost:8080/verify/result?token=" + token + "' style='color: #007bff;'>http://localhost:8080/verify/result?token=" + token + "</a>" +
                        "       </p>" +
                        "   </div>" +
                        "   <footer style='text-align: center; font-size: 12px; color: #777;'>" +
                        "       Email này được tạo ra trong quá trình đăng ký thành viên của Chill and Free Coffee. Nếu bạn có bất kỳ câu hỏi nào, vui lòng liên hệ với trung tâm hỗ trợ khách hàng.<br>" +
                        "       &copy; Chill and Free Coffee All Rights Reserved" +
                        "   </footer>" +
                        "</body>" +
                        "</html>";

        helper.setText(mailContent, true); // Cài đặt true để nội dung được hiểu là HTML.

        mailSender.send(message);
    }
    public void sendUserIdEmail(User user) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom("ducmanh16022002@gmail.com");
        helper.setTo(user.getEmail());
        helper.setSubject(user.getFull_name() + "Dear, Kết quả tìm kiếm ID Chill and Free Coffee của bạn.");

        String mailContent =
                "<html>" +
                        "<body style='font-family: Arial, sans-serif; color: #333;'>" +
                        "   <div style='max-width: 600px; margin: 20px auto; border: 1px solid #ddd; padding: 20px;'>" +
                        "       <h2 style='color: #007bff; text-align: center;'>Tìm kiếm ID Chill and Free Coffee </h2>" +
                        "       <p style='font-size: 16px;'>" +
                        "           Xin chào, <strong>" + user.getFull_name() + "</strong>! ID Chill and Free Coffee của bạn là:<br>" +
                        "           <strong>" + user.getUsername() + "</strong><br>" +
                        "           Để bảo mật, mật khẩu sẽ không được tiết lộ. Vui lòng sử dụng chức năng tìm mật khẩu nếu cần." +
                        "       </p>" +
                        "       <div style='text-align: center; margin: 40px 0;'>" +
                        "           <a href='http://localhost:8080/login'" +
                        "              style='display: inline-block; background-color: #007bff; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px;'>" +
                        "               Chuyển đến trang đăng nhập" +
                        "           </a>" +
                        "       </div>" +
                        "   </div>" +
                        "   <footer style='text-align: center; font-size: 12px; color: #777;'>" +
                        "       Email này được tạo ra trong quá trình yêu cầu tìm kiếm ID Seed. Nếu bạn có bất kỳ câu hỏi nào, vui lòng liên hệ với trung tâm hỗ trợ khách hàng.<br>" +
                        "       &copy; Chill and Free Coffee All Rights Reserved" +
                        "   </footer>" +
                        "</body>" +
                        "</html>";

        helper.setText(mailContent, true); // Cài đặt true để nội dung được hiểu là HTML.

        mailSender.send(message);
    }


    public PasswordResetToken createVerificationToken(User user) {
        PasswordResetToken myToken = null;
        String token = UUID.randomUUID().toString();
        Optional<PasswordResetToken> tokenOpt = verificationTokenService.findByUserId(user.getId());
        if (tokenOpt.isEmpty()) {
            myToken = new PasswordResetToken();
            myToken.setUser(user);
            myToken.setToken(token);
            myToken.setExpiryDate(LocalDateTime.now().plusHours(24)); // 24시간 후 만료
        } else {
            myToken = tokenOpt.get();
            myToken.setToken(token);
            myToken.setExpiryDate(LocalDateTime.now().plusHours(24)); // 24시간 후 만료
        }
        return verificationTokenService.save(myToken);
    }

    public boolean verifyToken(String token) {
        PasswordResetToken verificationToken = verificationTokenService.findByToken(token).orElse(null);
        if (verificationToken == null || verificationToken.isExpired()) {
            return false;
        }
        User user = verificationToken.getUser();
        userService.save(user);
        verificationTokenService.delete(verificationToken);
        return true;
    }

    public void sendEmailForgetPassword(String recipientEmail, String link)
            throws MessagingException, UnsupportedEncodingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setFrom("ducmanh16022002@gmail.com", "Chill And Free Coffee Support");
        helper.setTo(recipientEmail);

        String subject = "Here's the link to reset your password";

        String content = "<p>Hello,</p>"
                + "<p>You have requested to reset your password.</p>"
                + "<p>Click the link below to change your password:</p>"
                + "<p><a href=\"" + link + "\">Change my password</a></p>"
                + "<br>"
                + "<p>Ignore this email if you do remember your password, "
                + "or you have not made the request.</p>";

        helper.setSubject(subject);

        helper.setText(content, true);

        mailSender.send(message);
    }





    
}
