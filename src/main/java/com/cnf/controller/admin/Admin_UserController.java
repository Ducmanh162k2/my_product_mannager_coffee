package com.cnf.controller.admin;

import com.cnf.entity.Product;
import com.cnf.entity.User;
import com.cnf.services.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
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
@RequestMapping("admin/user")
public class Admin_UserController {
    @Autowired
    private UserService userService;
//    @GetMapping()
//    public String index(Model model){
//        return findPaginated(1, model);
//    }

    @GetMapping()
    public String index(Model model){
        List<User> listUser = userService.getAllUser();
        model.addAttribute("users", listUser);
        return "admin/user/index";
    }

    @GetMapping("/page/{pageNo}")
    public String findPaginated(@PathVariable(value = "pageNo") int pageNo, Model model) {
        int pageSize = 5;
        Page<User> page = userService.findPaginated(pageNo, pageSize);
        List<User> listUser = page.getContent();

        model.addAttribute("currentPage", pageNo);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("users", listUser);
        return "admin/user/index";
    }

    @GetMapping("/toggleActive/{id}")
    public String toggleActive(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        try {
            userService.toggleActiveStatus(id);
            redirectAttributes.addFlashAttribute("message","Active successfully!");
            return "redirect:/admin/user" ;
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("message","Failed to active user");
            return "redirect:/admin/user" ;

        }

    }





//    @GetMapping("/add")
//    public String addNew(Model model){
//        model.addAttribute("user", new Product());
//        model.addAttribute("roles", categoryService.getAllCategories());
//        return "admin/product/add";
//    }
//    @PostMapping("/add")
//    public String add(@Valid @ModelAttribute("product")Product product,
//                      BindingResult bindingResult, Model model,
//                      @RequestParam("image") MultipartFile multipartFile,
//                      RedirectAttributes redirectAttributes) throws IOException {
//
//        if (bindingResult.hasErrors()) {
//            List<FieldError> errors = bindingResult.getFieldErrors();
//            for (FieldError error : errors) {
//                model.addAttribute(error.getField() + "_error",
//                        error.getDefaultMessage());
//            }
//            model.addAttribute("categories", categoryService.getAllCategories());
//            return "admin/product/add";
//        }
//        productService.addProduct(product,multipartFile);
//        redirectAttributes.addFlashAttribute("message", "Save successfully!");
//        return "redirect:/admin/product";
//    }
//    @GetMapping("/edit/{id}")
//    public String edit(@PathVariable("id") Long id, Model model){
//        Product editProduct = null;
//        for(Product product: productService.getAllProducts()){
//            if(product.getId() == id){
//                editProduct = product;
//            }
//        }
//        if(editProduct != null){
//            model.addAttribute("product", editProduct);
//            model.addAttribute("categories", categoryService.getAllCategories());
//            return "admin/product/edit";
//        }else {
//            return "not-found";
//        }
//    }
}
