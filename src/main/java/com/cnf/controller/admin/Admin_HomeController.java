package com.cnf.controller.admin;

import com.cnf.services.OrderDetailsService;
import com.cnf.services.OrderService;
import com.cnf.services.ProductService;
import com.cnf.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/admin")
public class Admin_HomeController {
    @Autowired
    OrderService orderService;
    @Autowired
    ProductService productService;
    @Autowired
    UserService userService;
    @Autowired
    OrderDetailsService orderDetailsService;
    @GetMapping("")
    public String home(Model model){
        model.addAttribute("totalSales", orderService.getTotalSales());
        model.addAttribute("totalItems", productService.getAllProducts().size());
        model.addAttribute("users", userService.getAllUsers().size());
        model.addAttribute("orderDelivery", orderService.getOrderDelivery());
        model.addAttribute("getTopRevenue", orderDetailsService.getTop5ProductsByRevenue());
        return "admin/home/index";
    }
}
