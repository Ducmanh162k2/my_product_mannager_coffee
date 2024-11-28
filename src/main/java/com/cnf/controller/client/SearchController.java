package com.cnf.controller.client;

import com.cnf.entity.Product;
import com.cnf.services.CategoryService;
import com.cnf.services.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@Controller
public class SearchController {
    @Autowired
    private ProductService productService;
    @Autowired
    private CategoryService categoryService;
    @PostMapping("/search/product")
    public String searchProduct(@RequestParam("keyword") String keyword, Model model){
        List<Product> products = productService.searchProductByName(keyword);
        model.addAttribute("products", products);
        model.addAttribute("categories", categoryService.getAllCategories());
        return "client/search/index";
    }
}
