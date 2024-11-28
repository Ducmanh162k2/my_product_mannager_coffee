package com.cnf.controller.client;

import com.cnf.daos.Item;
import com.cnf.daos.ProductDTO;
import com.cnf.entity.Product;
import com.cnf.services.ProductService;
import com.cnf.services.WishListService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin(origins = "*")
public class WishListRestController {
    @Autowired
    private ProductService productService;
    @Autowired
    private WishListService wishListService;
    @GetMapping("/add-to-wishlist/{id}")
    public void addToCart(@PathVariable("id") Long id, HttpSession session,
                          @RequestParam(defaultValue = "1") int quantity)
    {
        Product product = null;
        for(Product temp: productService.getAllProducts()){
            if(temp.getId() == id){
                product = temp;
            }
        }
        if(product != null){
            var wishlist = wishListService.getCart(session);
            wishlist.addItems(new Item(id, product.getName(), product.getPrice(), quantity,product.getImagesPath()));
            wishListService.updateCart(session, wishlist);
        }
    }
    @GetMapping("/getProduct/{id}")
    public ProductDTO quickView(@PathVariable("id") Long id){
       Product product = productService.getProductById(id);
       ProductDTO productDTO = new ProductDTO();
       productDTO.setId(product.getId());
       productDTO.setName(product.getName());
       productDTO.setPrice(product.getPrice());
       productDTO.setImage(product.getImagesPath());
       productDTO.setQuantity(product.getQuantity());
       return productDTO;
    }
}
