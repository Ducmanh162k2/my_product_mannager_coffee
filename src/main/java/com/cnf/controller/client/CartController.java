package com.cnf.controller.client;

import com.cnf.config.vnpay.Config;
import com.cnf.entity.Orders;
import com.cnf.entity.User;
import com.cnf.services.*;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;


@Controller
@RequestMapping("/cart")
@RequiredArgsConstructor
public class CartController {
    private final CartService cartService;
    @Autowired
    private UserService userService;
    @Autowired
    private PaypalService paypalService;
    @Autowired
    private EmailSenderService emailSenderService;
    @Autowired
    private OrderService orderService;
    public static final String SUCCESS_URL = "paypal/success";
    public static final String CANCEL_URL = "paypal/cancel";
    @GetMapping
    public String showCart(HttpSession session, @NotNull Model model) {
        model.addAttribute("cart", cartService.getCart(session));
        model.addAttribute("totalPrice", cartService.getSumPrice(session));
        model.addAttribute("totalQuantity", cartService.getSumQuantity(session));
        session.setAttribute("totalItems", cartService.getSumQuantity(session));
        return "client/cart/index";
    }
    @GetMapping("/removeFromCart/{id}")
    public String removeFromCart(HttpSession session, @PathVariable Long id) {
        var cart = cartService.getCart(session);
        cart.removeItems(id);
        return "redirect:/cart";
    }
    @GetMapping("/updateCart/{id}/{quantity}")
    public String updateCart(HttpSession session, @PathVariable Long id, @PathVariable int quantity) {
        var cart = cartService.getCart(session);
        cart.updateItems(id, quantity);
        return "redirect:/cart ";
    }
    @GetMapping("/clearCart")
    public String clearCart(HttpSession session) {
        cartService.removeCart(session);
        return "redirect:/cart";
    }
    @GetMapping("/checkout")
    public String checkoutView(Model model, HttpSession session){

        if(model.containsAttribute("message")){
            model.addAttribute("message", model.getAttribute("message"));
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        model.addAttribute("user", user);
        model.addAttribute("cart", cartService.getCart(session));
        model.addAttribute("totalPrice", cartService.getSumPrice(session));
        return "client/cart/checkout";
    }
    @PostMapping("/checkout")
    public String checkout(@RequestParam("address") String address,
                           @RequestParam("phone") String phone,
                           @RequestParam(name = "note", defaultValue = "") String note,
                           @RequestParam(name = "cash", defaultValue = "false") boolean cash,
                           @RequestParam(name = "paypal",defaultValue = "false") boolean paypal,
                           @RequestParam(name = "vnPay", defaultValue = "false") boolean vnPay ,HttpSession session,
                           RedirectAttributes redirectAttributes,final HttpServletRequest request) throws UnsupportedEncodingException {

        int count = 0;
        if(cash) count ++;
        if(paypal) count ++;
        if(vnPay) count ++;
        if(count >= 2){
            redirectAttributes.addFlashAttribute("message", "message");
            return "redirect:/cart/checkout";
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        session.setAttribute("note", note);
        session.setAttribute("address",address);
        session.setAttribute("phone",phone);
        if(cash){
            cartService.saveCart(session,phone,note,address,user,"cash");
            return "redirect:/cart/success";
        }
        if(paypal){
            return "redirect:/cart/paypal_checkout";
        }
        if(vnPay){
            double totalMoney = cartService.getSumPrice(session);
            long vnpay_Amount = (long) (totalMoney * 100);
            String vnpayPaymentUrl = paymentVnpay(vnpay_Amount, request);
            return "redirect:"+vnpayPaymentUrl;
        }
        redirectAttributes.addFlashAttribute("message", "message");
        return "redirect:/cart/checkout";
    }
    private String applicationUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }
    private String paymentVnpay(long send_amount, HttpServletRequest request) throws UnsupportedEncodingException {
        //Thanh toán VNPAY
        long amount = send_amount;
        String vnp_TxnRef = Config.getRandomNumber(8);
        String vnp_TmnCode = Config.vnp_TmnCode;

        Map<String, String> vnp_Params = new HashMap<>();
        vnp_Params.put("vnp_Version", Config.vnp_Version);
        vnp_Params.put("vnp_Command", Config.vnp_Command);
        vnp_Params.put("vnp_TmnCode", vnp_TmnCode);
        vnp_Params.put("vnp_Amount", String.valueOf(amount));
        vnp_Params.put("vnp_CurrCode", "VND");
        String vnp_IpAddr = Config.getIpAddress(request);
        vnp_Params.put("vnp_IpAddr", vnp_IpAddr);
        // vnp_Params.put("vnp_BankCode", "NCB");
        vnp_Params.put("vnp_TxnRef", vnp_TxnRef);
        vnp_Params.put("vnp_OrderInfo", String.valueOf(System.currentTimeMillis()));
        vnp_Params.put("vnp_OrderType", "billpayment");
        vnp_Params.put("vnp_Locale", "vn");

        String vnp_Returnurl = applicationUrl(request) + "/cart/vnpay-payment-result";
        vnp_Params.put("vnp_ReturnUrl", vnp_Returnurl);

        Calendar cld = Calendar.getInstance(TimeZone.getTimeZone("Etc/GMT+7"));
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
        String vnp_CreateDate = formatter.format(cld.getTime());
        vnp_Params.put("vnp_CreateDate", vnp_CreateDate);

        cld.add(Calendar.MINUTE, 15);
        String vnp_ExpireDate = formatter.format(cld.getTime());
        vnp_Params.put("vnp_ExpireDate", vnp_ExpireDate);

        List fieldNames = new ArrayList(vnp_Params.keySet());
        Collections.sort(fieldNames);
        StringBuilder hashData = new StringBuilder();
        StringBuilder query = new StringBuilder();
        Iterator itr = fieldNames.iterator();
        while (itr.hasNext()) {
            String fieldName = (String) itr.next();
            String fieldValue = (String) vnp_Params.get(fieldName);
            if ((fieldValue != null) && (fieldValue.length() > 0)) {
                //Build hash data
                hashData.append(fieldName);
                hashData.append('=');
                hashData.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                //Build query
                query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString()));
                query.append('=');
                query.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));
                if (itr.hasNext()) {
                    query.append('&');
                    hashData.append('&');
                }
            }
        }
        String queryUrl = query.toString();
        String vnp_SecureHash = Config.hmacSHA512(Config.vnp_HashSecret, hashData.toString());
        queryUrl += "&vnp_SecureHash=" + vnp_SecureHash;
        String paymentUrl = Config.vnp_PayUrl + "?" + queryUrl;
        System.out.println("Called: " + paymentUrl);
        return paymentUrl;
    }
    @GetMapping("/vnpay-payment-result")
    public String showResult(@RequestParam("vnp_ResponseCode") String responseCode, HttpSession session,RedirectAttributes redirectAttributes
    ) throws MessagingException, UnsupportedEncodingException {
        if (responseCode.equals("00")) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            User user = userService.findByUsername1(email).orElseThrow();
            //save
            String note =(String)session.getAttribute("note");
            String address = (String)session.getAttribute("address");
            String phone = (String)session.getAttribute("phone");
            cartService.saveCart(session,phone,note,address,user,"vnPay");
            return "redirect:/cart/success";
        }
        redirectAttributes.addFlashAttribute("message", "Có lỗi xảy ra khi thanh toán");
        return "redirect:/cart/checkout";
    }
    @GetMapping("/paypal_checkout")
    public String paypalCheckout(HttpSession session){
        try {
            //get price
            double totalMoney = cartService.getSumPrice(session);
            double USD  = totalMoney / 23000;
            Payment payment = paypalService.createPayment(USD, "USD",
                    "paypal","sale","Organic Store",
                    "http://localhost:8080/cart/" + CANCEL_URL,
                    "http://localhost:8080/cart/" + SUCCESS_URL);
            for(Links link:payment.getLinks()) {
                if(link.getRel().equals("approval_url")) {
                    return "redirect:"+link.getHref();
                }
            }
        } catch (PayPalRESTException e) {
            e.printStackTrace();
        }
        return "redirect:/cart/checkout";
    }
    @GetMapping(value = SUCCESS_URL)
    public String paypalSuccess(@RequestParam("paymentId") String paymentId,
                                @RequestParam("PayerID") String payerId, HttpSession session){
        try {
            Payment payment = paypalService.executePayment(paymentId, payerId);
            System.out.println(payment.toJSON());
            if (payment.getState().equals("approved")) {
                //get user
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String username = authentication.getName();
                User user = userService.getUserbyUserName(username);
                //save
                String note =(String)session.getAttribute("note");
                String address = (String)session.getAttribute("address");
                String phone = (String)session.getAttribute("phone");
                cartService.saveCart(session,phone,note,address,user,"paypal");
                return "redirect:/cart/success";
            }
        } catch (PayPalRESTException e) {
            System.out.println(e.getMessage());
        }
        return "redirect:/cart/checkout";
    }
    public String formatPrice(Double amount){
        String formattedAmount = StringUtils.replaceEach(
                String.format("%.2f", amount),
                new String[] {".", ","},
                new String[] {",", "."}
        ) + " VNĐ";
        return  formattedAmount;
    }
    @GetMapping("/success")
    public String checkoutSuccess(HttpSession session) throws MessagingException, UnsupportedEncodingException {
        //get user email
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        String email = user.getEmail();
        //get order information
        Long orderID = (Long) session.getAttribute("orderID");
        Orders order = orderService.getOrderById(orderID);
        Double sumPrice = (Double) session.getAttribute("sumPrice");
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy");
        String method;
        if(order.isPayment())
            method = "Paypal";
        else
            method = "Cash on Delivery";

        String subject = "Order Confirmation - Order number: #" + orderID;

        String body = "<h3>Hello, " +user.getFull_name()+ "</h3>";
        body += "Order number: #"+orderID;
        body += "<p>Order date: "+ dateFormat.format(order.getDate_purchase())+"</p>";
        body += "<p style=\"margin-top: 20px\">Total amount: "+ "<span style=\"font-weight: bold\">"+formatPrice(sumPrice) +" </span>" +"</p>";
        body += "<p>Payment Method: "+method+"</p>";
        body += "<h3 style=\"margin-top: 20px\">Shipping Address: </h3>" +
                "<p>" +user.getFull_name()+"</p>" +
                "<p>" +order.getAddress() +"</p>" +
                "<p>" +order.getPhone().split(",")[1]+ "</p>";
        body += "<h3 style=\"margin-top: 20px\">Thank you for choosing our products!!</h3>";

        emailSenderService.sendEmail(email,subject,body);
        return "client/cart/success";
    }
    @GetMapping(value =CANCEL_URL)
    public String checkoutCancel(){
        return "client/cart/cancel";    
    }
}
