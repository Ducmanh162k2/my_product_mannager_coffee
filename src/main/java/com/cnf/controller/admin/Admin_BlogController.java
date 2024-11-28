package com.cnf.controller.admin;

import com.cnf.entity.Blog;
import com.cnf.services.BlogService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.util.List;

@Controller
@RequestMapping("/admin/blog")
public class Admin_BlogController {
    @Autowired
    BlogService blogService;
    @GetMapping()
    public String index(Model model){
        model.addAttribute("blogs", blogService.getAllBlogs());
        return "admin/blog/index";
    }
    @GetMapping("/add")
    public String addNew(Model model){
        model.addAttribute("blog", new Blog());
        return "admin/blog/add";
    }
    @PostMapping("/add")
    public String add(@Valid @ModelAttribute("blog")Blog blog,
                      BindingResult bindingResult, Model model,
                      @RequestParam("description") String description,
                      @RequestParam("image") MultipartFile multipartFile,
                      RedirectAttributes redirectAttributes) throws IOException {

        if (bindingResult.hasErrors()) {
            List<FieldError> errors = bindingResult.getFieldErrors();
            for (FieldError error : errors) {
                model.addAttribute(error.getField() + "_error",
                        error.getDefaultMessage());
            }
            return "admin/blog/add";
        }
        blogService.addBlog(blog,description, multipartFile);
        redirectAttributes.addFlashAttribute("message", "Save successfully!");
        return "redirect:/admin/blog";
    }
    @GetMapping("/edit/{id}")
    public String edit(@PathVariable("id") Long id, Model model){
        Blog blog = blogService.getBlogById(id);
        model.addAttribute("blog", blog);
        return "admin/blog/edit";
    }
    @PostMapping("/edit")
    public String edit(@Valid @ModelAttribute("blog") Blog updateBlog,
                       Model model, @RequestParam("description") String description,
                       @RequestParam("image") MultipartFile multipartFile,
                       RedirectAttributes redirectAttributes) throws IOException {

        blogService.updateBlog(updateBlog, description, multipartFile);
        redirectAttributes.addFlashAttribute("message", "Save successfully!");
        return "redirect:/admin/blog";
    }

    @GetMapping("/delete/{id}")
    public String deleteBlog(@PathVariable("id") Long id, RedirectAttributes redirectAttributes ) {
        try {
            blogService.deleteBlogById(id);
            redirectAttributes.addFlashAttribute("message","Delete successfully!");
            return "redirect:/admin/blog" ;
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("message","Failed to delete product");
            return "redirect:/admin/blog" ;

        }
    }
}
