package com.cnf.controller.client;

import com.cnf.entity.Product;
import com.cnf.entity.User;
import com.cnf.services.*;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.List;

@Controller
@RequestMapping("/product")
public class ProductController {
    @Autowired
    private ProductService productService;
    @Autowired
    private CategoryService categoryService;
    @Autowired
    private CartService cartService;
    @Autowired
    private UserService userService;
    @Autowired
    private CommentService commentService;
    @GetMapping()
    public String index(Model model,HttpSession session){

        return findPaginated(1, model);
    }
    @GetMapping("/page/{pageNo}")
    public String findPaginated(@PathVariable (value = "pageNo") int pageNo, Model model) {
        int pageSize = 12;
        Page<Product> page = productService.findPaginated(pageNo, pageSize);
        List<Product> list = page.getContent();
        List<Product> listProduct = new ArrayList<>();
        for(Product product: list) {
            if(product.getActive()) {
                listProduct.add(product);
            }
        }

        model.addAttribute("currentPage", pageNo);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("categories", categoryService.getAllCategories());
        model.addAttribute("products", listProduct);
        return "client/product/index";
    }
    @GetMapping("/detail/{id}")
    public String detail(@PathVariable("id") Long id, Model model, HttpSession session){
        Product product = null;
        for(Product temp: productService.getAllProducts()){
            if(temp.getId() == id){
                product = temp;
            }
        }
        if(product != null){

            model.addAttribute("total_comments", product.getTotalComments());
            model.addAttribute("average_rating", product.getAverageRating());
            model.addAttribute("product", product);
            model.addAttribute("top_rated_product", productService.getTopRatedProduct());
            model.addAttribute("product_related", productService.getALlProductsByCategoryId(product.getCategory().getId()));
            model.addAttribute("categories", categoryService.getAllCategories());
            return "client/product/detail";
        }else {
            return "not-found";
        }
    }
    @GetMapping("/category/{id}")
    public String productsByCategory(@PathVariable("id") Long id, Model model,HttpSession session){
        model.addAttribute("products", productService.getALlProductsByCategoryId(id));
        model.addAttribute("categories", categoryService.getAllCategories());

        session.setAttribute("totalItems", cartService.getSumQuantity(session));
        session.setAttribute("cart", cartService.getCart(session));
        session.setAttribute("totalPrice", cartService.getSumPrice(session));
        return "client/product/category";
    }
    @PostMapping("/comment")
    public String writeComment(@RequestParam("comment-text") String text, @RequestParam("rate") int rating,
                                   @RequestParam("productID") long productID, RedirectAttributes redirectAttributes){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        Product product = productService.getProductById(productID);
        commentService.addComment(user,product,text,rating);
        return "redirect:/product/detail/" + productID;
    }
}
