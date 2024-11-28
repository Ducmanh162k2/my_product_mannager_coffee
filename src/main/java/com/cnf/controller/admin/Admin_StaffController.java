package com.cnf.controller.admin;

import com.cnf.entity.Product;
import com.cnf.entity.User;
import com.cnf.services.UserService;
import jakarta.servlet.http.HttpServletRequest;
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
@RequestMapping("admin/staff_user")
public class Admin_StaffController {
    @Autowired
    private UserService userService;
//    @GetMapping()
//    public String index(Model model){
//        return findPaginated(1, model);
//    }
    @GetMapping()
    public String index(Model model){
        List<User> listStaff = userService.getAllSatff();
        model.addAttribute("users", listStaff);
        return "admin/staff_user/index";
    }
    @GetMapping("/page/{pageNo}")
    public String findPaginated(@PathVariable(value = "pageNo") int pageNo, Model model) {
        int pageSize = 5;
        Page<User> page = userService.findPaginatedStaff(pageNo, pageSize);
        List<User> listStaff = page.getContent();

        model.addAttribute("currentPage", pageNo);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("users", listStaff);
        return "admin/staff_user/index";
    }
    @GetMapping("/add")
    public String addNew(Model model){
        model.addAttribute("staff", new User());
        return "admin/staff_user/add";
    }
    @PostMapping("/add")
    public String add(@Valid @ModelAttribute("staff") User staff,
                      BindingResult bindingResult, Model model
    ) throws IOException {
        if (bindingResult.hasErrors()) {
            List<FieldError> errors = bindingResult.getFieldErrors();
            for (FieldError error : errors) {
                model.addAttribute(error.getField() + "_error",
                        error.getDefaultMessage());
            }
            return "admin/staff_user/add";
        }

        List<User> users = userService.getAllUsers();
        for (User user1 : users) {
            if (user1.getEmail().equals(staff.getEmail())) {
                model.addAttribute("messEmail", "Email was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/add";
            }else  if (user1.getPhone()!=null && user1.getPhone().equals(staff.getPhone())) {
                model.addAttribute("messPhone", "Phone was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/add";
            }else  if (user1.getUsername().equals(staff.getUsername())) {
                model.addAttribute("messUserName", "UserName was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/add";
            }
        }
        staff.setActive(true);
        userService.saveStaff(staff);
        return "redirect:/admin/staff_user";
    }

    private String emailDefault = "";
    private String phoneDefault = "";
    private String userNameDefault = "";

    @GetMapping("/edit/{id}")
    public String edit(@PathVariable("id") Long id, Model model){

        User editStaff = null;
        for(User staff: userService.getAllSatff()){
            if(staff.getId() == id){
                editStaff = staff;
            }
        }
        if(editStaff != null){
            emailDefault = editStaff.getEmail();
            phoneDefault = editStaff.getPhone();
            userNameDefault = editStaff.getUsername();

            model.addAttribute("staff", editStaff);
            return "admin/staff_user/edit";
        }else {
            return "not-found";
        }
    }

    @PostMapping("edit")
    public String edit(@Valid @ModelAttribute("staff") User staff,
                       BindingResult bindingResult, Model model,
                       RedirectAttributes redirectAttributes, HttpServletRequest request) throws IOException {

        List<User> users = userService.getAllUsers();
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        for (User user1 : users) {
            if (!staff.getEmail().equals(emailDefault) && user1.getEmail().equals(staff.getEmail())) {
                model.addAttribute("messEmail", "Email was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/edit";
            }else  if ( !staff.getPhone().equals(phoneDefault) && user1.getPhone()!=null && user1.getPhone().equals(staff.getPhone())) {
                model.addAttribute("messPhone", "Phone was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/edit";
            }else  if (!staff.getUsername().equals(userNameDefault) && user1.getUsername().equals(staff.getUsername())) {
                model.addAttribute("messUserName", "UserName was existed");
                model.addAttribute("user", staff);
                return "admin/staff_user/edit";
            }
        }
        userService.updateStaff(staff);
        redirectAttributes.addFlashAttribute("message", "Save successfully!");
        return "redirect:/admin/staff_user";
    }

    @GetMapping("/toggleActive/{id}")
    public String toggleActive(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
        try {
            userService.toggleActiveStatus(id);
            redirectAttributes.addFlashAttribute("message","Active successfully!");
            return "redirect:/admin/staff_user" ;
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("message","Failed to active user");
            return "redirect:/admin/staff_user" ;

        }

    }
}
