package com.cnf.controller.client;

import com.cnf.services.BlogService;
import com.cnf.services.EmailSenderService;
import com.cnf.services.ProductService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.UnsupportedEncodingException;


@Controller
@RequestMapping("/")
public class HomeController {
    @Autowired
    private ProductService productService;
    @Autowired
    private BlogService blogService;
    @Autowired
    private EmailSenderService emailSenderService;
    @GetMapping("")
    public String home(Model model, HttpSession session){
        model.addAttribute("product_1", productService.getALlProductsByCategoryId(1L));
        model.addAttribute("product_2", productService.getALlProductsByCategoryId(2L));
        model.addAttribute("product_3", productService.getALlProductsByCategoryId(3L));
        model.addAttribute("product_4", productService.getALlProductsByCategoryId(4L));
        model.addAttribute("blogs", blogService.getAllBlogs());
        return "client/home/index";
    }
    @GetMapping("about")
    public String about(){
        return "client/home/about";
    }
    @GetMapping("contact")
    public String contact(Model model){
        if(model.containsAttribute("message")){
            model.addAttribute("message", model.getAttribute("message"));
        }
        return "client/home/contact";
    }
    @PostMapping("sendEmail")
    public String sendEmail(@RequestParam("name")String name,@RequestParam("email")String email,
                            @RequestParam("phone")String phone, @RequestParam("message")String message,
                            @RequestParam("service") String service, RedirectAttributes redirectAttributes) throws MessagingException, UnsupportedEncodingException {

        String subject = "Contact form";
        String body = "<h3>Information</h3>";
        body += "<p>Name: "+name + "</p>";
        body += "<p>Email: "+ email+"</p>";
        body += "<p>Phone number: "+ phone+"</p>";
        body += "<p>Service type: "+service+"</p>";
        body += "<p>Message:" + message + "</p>";
        emailSenderService.sendEmailContact(email,subject,body);
        redirectAttributes.addFlashAttribute("message", "Send successfully!");
        return "redirect:/contact";
    }
}
