package com.cnf.controller.client;


import com.cnf.entity.User;
import com.cnf.services.EmailSenderService;
import com.cnf.services.PasswordResetTokenService;
import com.cnf.services.UserService;
import com.cnf.validatiors.UserAuthValidator;
import jakarta.mail.MessagingException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
@RequestMapping("/verify")
public class UserVerificationController {

    private final UserService userService;
    private final UserAuthValidator userAuthValidator;
    private final EmailSenderService emailService;
    private final PasswordResetTokenService verificationTokenService;

    @GetMapping("/result")
    public String verifyUser(@RequestParam("token") String token) {
        if (emailService.verifyToken(token)) {
            verificationTokenService.deleteByToken(token);
            return "verifyByEmail/verify_success";
        } else {
            return "verifyByEmail/verify_fail";
        }
    }

    @GetMapping
    public String verifyForm(@RequestParam("username") String username, Model model) {
        User user = userAuthValidator.getCurrentUserByUsername(username);
        model.addAttribute("user", user);
        return "verifyByEmail/verification_email";
    }

    @PostMapping("/send")
    public String emailSend(@RequestParam("username") String username, @RequestParam("email") String email) throws MessagingException {
        User user = userAuthValidator.getCurrentUserByUsername(username);
        String userEmailOrigin = user.getEmail();
        if (!userEmailOrigin.equals(email)) {
            user.setEmail(email);
            userService.save(user);
        }
        emailService.sendVerificationEmail(user);

        return "redirect:/";
    }
}

