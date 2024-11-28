package com.cnf.controller.client;

import com.cnf.daos.OrderDTO;
import com.cnf.entity.Orders;
import com.cnf.entity.User;
import com.cnf.services.CartService;
import com.cnf.services.OrderService;
import com.cnf.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class OrderRestController {
    @Autowired
    private OrderService orderService;
    @Autowired
    private UserService userService;
    @Autowired
    private CartService cartService;
    @GetMapping("/cancel_order/{id}")
    public void cancelOrder(@PathVariable("id") Long id ){
        orderService.cancelOrder(id);
    }
    @GetMapping("/getOrders")
    public List<OrderDTO> getAllOrder(Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        var orders = orderService.getAllOrdersByUserId(user.getId());
        List<OrderDTO> orderDTOs = convertToDTO(orders);
        return orderDTOs;
    }

    private List<OrderDTO> convertToDTO(List<Orders> orders) {
        List<OrderDTO> orderDTOs = new ArrayList<>();
        for (Orders order : orders) {
            OrderDTO orderDTO = new OrderDTO();
            orderDTO.setId(order.getId());
            orderDTO.setDate_purchase(order.getDate_purchase());
            orderDTO.setStatus_id(order.getStatus_order().getId());
            orderDTO.setStatus_name(order.getStatus_order().getName());
            orderDTO.setTotal_money(order.getTotal_money());
            orderDTOs.add(orderDTO);
        }
        return orderDTOs;
    }
}
