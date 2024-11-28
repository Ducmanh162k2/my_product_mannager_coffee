package com.cnf.services;

import com.cnf.daos.Cart;
import com.cnf.daos.Item;
import com.cnf.entity.OrderDetails;
import com.cnf.entity.Orders;
import com.cnf.entity.User;
import com.cnf.repository.IOderDetailsRepository;
import com.cnf.repository.IOrderRepository;
import com.cnf.repository.IProductRepository;
import com.cnf.repository.IStatusOrderRepository;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;


import java.util.Date;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(isolation = Isolation.SERIALIZABLE, rollbackFor = {Exception.class, Throwable.class})
public class CartService {
    private static final String CART_SESSION_KEY = "cart";
    private final IOrderRepository orderRepository;
    private final IOderDetailsRepository oderDetailsRepository;
    private final IProductRepository productRepository;
    private final IStatusOrderRepository statusOrderRepository;

    public Cart getCart(@NotNull HttpSession session) {
        return Optional.ofNullable((Cart)
                        session.getAttribute(CART_SESSION_KEY))
                .orElseGet(() -> {
                    Cart cart = new Cart();
                    session.setAttribute(CART_SESSION_KEY, cart);
                    return cart;
                });
    }
    public void updateCart(@NotNull HttpSession session, Cart cart) {
        session.setAttribute(CART_SESSION_KEY, cart);
    }
    public void removeCart(@NotNull HttpSession session) {
        session.removeAttribute(CART_SESSION_KEY);
    }
    public int getSumQuantity(@NotNull HttpSession session) {
        return getCart(session).getCartItems().stream()
                .mapToInt(Item::getQuantity)
                .sum();
    }
    public int getQuantity(@NotNull HttpSession session){
        return getCart(session).getCartItems().size();
    }
    public double getSumPrice(@NotNull HttpSession session) {
        return getCart(session).getCartItems().stream()
                .mapToDouble(item -> item.getPrice() *
                        item.getQuantity())
                .sum();
    }
//    public void updateStockFromCartWhenOrder(Cart cart) {
//        for (Item cartItem : cart.getCartItems()) {
//            Optional<Product> productOptional = productRepository.findById(cartItem.getProductId());
//            if (productOptional.isPresent()) {
//                Product product = productOptional.get();
//                float quantityInCart = cartItem.getQuantity() * product.getWeight();
//                // Kiểm tra xem số lượng trong cơ sở dữ liệu có đủ để trừ không
//                if (product.getQuantity() >= quantityInCart) {
//                    product.setQuantity(product.getQuantity() - quantityInCart);
//                    productRepository.save(product);
//                }
//            }
//        }
//    }
//    public void updateStockFromCartWhenCancel(Long orderID) {
//        var orders = oderDetailsRepository.findAllOrderDetailsByOrderId(orderID);
//        for (OrderDetails order : orders) {
//            Optional<Product> productOptional = productRepository.findById(order.getProduct().getId());
//            if (productOptional.isPresent()) {
//                Product product = productOptional.get();
//                float quantityInCart = order.getQuantity() * product.getWeight();
//                product.setQuantity(product.getQuantity() + quantityInCart);
//                productRepository.save(product);
//            }
//        }
//    }
    public void saveCart(@NotNull HttpSession session,String phone, String note, String address, User user, String payment) {
        var cart = getCart(session);
        if (cart.getCartItems().isEmpty()) return;
        var order = new Orders();
        order.setDate_purchase(new Date(new Date().getTime()));
        order.setTotal_money(getSumPrice(session));
        order.setNote(note);
        order.setPhone(phone);
        order.setAddress(address);
        order.setUser(user);
        order.setStatus_order(statusOrderRepository.findById(1L).orElseThrow());
        if(payment.equals("cash"))
            order.setPayment(false);
        if(payment.equals("paypal"))
            order.setPayment(true);
        if(payment.equals("vnPay"))
            order.setPayment(true);
        orderRepository.save(order);

        cart.getCartItems().forEach(item -> {
            var items = new OrderDetails();
            items.setOrders(order);
            items.setQuantity(item.getQuantity());
            items.setTotal_money(item.getPrice()*item.getQuantity());
            items.setProduct(productRepository.findById(item.getProductId()).orElseThrow());
            oderDetailsRepository.save(items);
        });
        session.setAttribute("orderID", order.getId());
        session.setAttribute("sumPrice", getSumPrice(session));
        removeCart(session);
    }

}
