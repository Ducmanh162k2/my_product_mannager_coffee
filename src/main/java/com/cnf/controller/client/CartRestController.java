package com.cnf.controller.client;
import com.cnf.daos.Item;
import com.cnf.entity.Product;
import com.cnf.services.CartService;
import com.cnf.services.ProductService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class CartRestController {
    @Autowired
    private ProductService productService;
    @Autowired
    private CartService cartService;
    @GetMapping("/add-to-cart/{id}/{quantity}")
    public void addToCart(@PathVariable("id") Long id, HttpSession session,
                           @PathVariable("quantity") int quantity)
    {
        Product product = null;
        for(Product temp: productService.getAllProducts()){
            if(temp.getId() == id){
                product = temp;
            }
        }
        if(product != null){
            var cart = cartService.getCart(session);
            cart.addItems(new Item(id, product.getName(), product.getPrice(), quantity,product.getImagesPath()));
            cartService.updateCart(session, cart);
        }
    }
    @GetMapping("/total_items")
    public int getTotalItems( HttpSession session){
        if(cartService.getCart(session) == null)
            return 0;
        return cartService.getQuantity(session);
    }
    @GetMapping("/getCart")
    public List<Item> getCart(HttpSession session){
        return cartService.getCart(session).getCartItems();
    }
    @GetMapping("/getSumPrice")
    public double getSumPrice(HttpSession session){
        return cartService.getSumPrice(session);
    }
}
