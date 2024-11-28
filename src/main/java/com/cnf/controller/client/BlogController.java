package com.cnf.controller.client;

import com.cnf.entity.User;
import com.cnf.services.BlogService;
import com.cnf.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/blog")
public class BlogController {
    @Autowired
    BlogService blogService;
    @Autowired
    UserService userService;
    @GetMapping("/detail/{id}")
    public String blogDetails(@PathVariable("id") Long id, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        if(user != null)
            model.addAttribute("userID", user.getId());

        model.addAttribute("blog", blogService.getBlogById(id));
        model.addAttribute("relatedBlog", blogService.getRelatedBlogs());
        model.addAttribute("blogs", blogService.getAllBlogs());
        return "client/blog/details";
    }

}
