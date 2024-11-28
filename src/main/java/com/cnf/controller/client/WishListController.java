package com.cnf.controller.client;


import com.cnf.services.WishListService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/wishlist")
@RequiredArgsConstructor
public class WishListController {
    private final WishListService wishlistService;
    @GetMapping()
    public String showWishList(HttpSession session, @NotNull Model model) {
        model.addAttribute("wishlist", wishlistService.getCart(session));
        return "client/wishlist/index";
    }
    @GetMapping("/removeFromWishList/{id}")
    public String removeFromCart(HttpSession session, @PathVariable Long id) {
        var wishlist = wishlistService.getCart(session);
        wishlist.removeItems(id);
        return "redirect:/wishlist";
    }
}
