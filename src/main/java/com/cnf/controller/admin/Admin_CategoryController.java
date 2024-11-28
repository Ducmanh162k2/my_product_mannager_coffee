package com.cnf.controller.admin;


import com.cnf.entity.Category;
import com.cnf.services.CategoryService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;


@Controller
@RequestMapping("/admin/category")
public class Admin_CategoryController {
    @Autowired
    private CategoryService categoryService;
//    @GetMapping("")
//    public String index(Model model){
//
//        if(model.containsAttribute("message")){
//            model.addAttribute("message", model.getAttribute("message"));
//        }
//        return findPaginated(1,model);
//    }

    @GetMapping("")
    public String index(Model model){

        if(model.containsAttribute("message")){
            model.addAttribute("message", model.getAttribute("message"));
        }
        List<Category> listCategory = categoryService.getAllCategories();
        model.addAttribute("categories", listCategory);
        return "admin/category/index";
    }

    @GetMapping("/page/{pageNo}")
    public String findPaginated(@PathVariable (value = "pageNo") int pageNo, Model model) {
        int pageSize = 5;
        Page<Category> page = categoryService.findPaginated(pageNo, pageSize);
        List<Category> listCategory = page.getContent();

        model.addAttribute("currentPage", pageNo);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("categories", listCategory);
        return "admin/category/index";
    }
    @GetMapping("/add")
    public String addNew(Model model){
        model.addAttribute("category", new Category());
        return "admin/category/add";
    }
    @PostMapping("/add")
        public String add(@Valid @ModelAttribute("category") Category category,
                          BindingResult bindingResult,
                          RedirectAttributes redirectAttributes, Model model){
        if (bindingResult.hasErrors()) {
            List<FieldError> errors = bindingResult.getFieldErrors();
            for (FieldError error : errors) {
                model.addAttribute(error.getField() + "_error",
                        error.getDefaultMessage());
            }
            return "admin/category/add";
        }
        categoryService.addCategory(category);
        redirectAttributes.addFlashAttribute("message", "Save successfully!");
        return "redirect:/admin/category";
    }
    @GetMapping("/edit/{id}")
    public String edit(@PathVariable("id") Long id, Model model){
        Category editCategory = null;
        for(Category category: categoryService.getAllCategories()){
            if(category.getId() == id){
                editCategory = category;
            }
        }
        if(editCategory != null){
            model.addAttribute("category", editCategory);
            return "admin/category/edit";
        }else {
            return "not-found";
        }
    }

    @PostMapping("/edit")
    public String edit(@Valid @ModelAttribute("category") Category updateCategory,
                       BindingResult bindingResult ,Model model,
                       RedirectAttributes redirectAttributes){
        if (bindingResult.hasErrors()) {
            List<FieldError> errors = bindingResult.getFieldErrors();
            for (FieldError error : errors) {
                model.addAttribute(error.getField() + "_error",
                        error.getDefaultMessage());
            }
            model.addAttribute("category", updateCategory);
            return "admin/category/edit";
        }
        categoryService.updateCategory(updateCategory);
        redirectAttributes.addFlashAttribute("message", "Save successfully!");
        return "redirect:/admin/category";
    }

}
