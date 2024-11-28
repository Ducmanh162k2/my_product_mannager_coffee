package com.cnf.controller.admin;

import com.cnf.entity.Orders;
import com.cnf.services.OrderDetailsService;
import com.cnf.services.OrderService;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.ByteArrayOutputStream;
import java.time.LocalDate;
import java.util.List;

@Controller
@RequestMapping("/admin/order")
public class Admin_OrderController {
    @Autowired
    private OrderService orderService;
    @Autowired
    private OrderDetailsService orderDetailsService;

    @GetMapping("")
    public String index(Model model){
        List<Orders> listOrder = orderService.getAllOrders();
        model.addAttribute("orders", listOrder);
        return "admin/order/index";
       // return findPaginated(1, model);
    }
    @GetMapping("/page/{pageNo}")
    public String findPaginated(@PathVariable (value = "pageNo") int pageNo, Model model) {
        int pageSize = 5;
        Page<Orders> page = orderService.findPaginated(pageNo, pageSize);
        List<Orders> listOrder = page.getContent();

        model.addAttribute("currentPage", pageNo);
        model.addAttribute("totalPages", page.getTotalPages());
        model.addAttribute("totalItems", page.getTotalElements());

        model.addAttribute("orders", listOrder);
        return "admin/order/index";
    }
    @GetMapping("/confirm_order/{id}")
    public String confirmOrder(@PathVariable("id") Long id, Model model){
        orderService.updateStatusOrder(id);
        return "redirect:/admin/order";
    }
    @GetMapping("/confirm_shipped/{id}")
    public String confirmShipped(@PathVariable("id") Long id, Model model){
        orderService.updateStatusOrder(id);
        return "redirect:/admin/order";
    }
    @GetMapping("/details/{id}")
    public String viewDetails(@PathVariable("id") Long id, Model model){
        model.addAttribute("order_details", orderDetailsService.getAllOrderDetailsByOrderId(id));
        return "admin/order/details";
    }

    @GetMapping("/export")
    public ResponseEntity<byte[]> exportOrdersToExcel(
            @RequestParam(value = "search", required = false) String search,
            @RequestParam(value = "status", required = false) Integer status,
            @RequestParam(value = "startDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
            @RequestParam(value = "endDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate) {

        List<Orders> orders = orderService.getFilteredOrders(search, status, startDate, endDate);

        try (Workbook workbook = new XSSFWorkbook()) {
            Sheet sheet = workbook.createSheet("Orders");
            Row header = sheet.createRow(0);
            header.createCell(0).setCellValue("ID");
            header.createCell(1).setCellValue("Date Purchase");
            header.createCell(2).setCellValue("Address");
            header.createCell(3).setCellValue("Payment Method");
            header.createCell(4).setCellValue("Total Money");
            header.createCell(5).setCellValue("Status");

            int rowNum = 1;
            for (Orders order : orders) {
                Row row = sheet.createRow(rowNum++);
                row.createCell(0).setCellValue(order.getId());
                row.createCell(1).setCellValue(order.getDate_purchase().toString());
                row.createCell(2).setCellValue(order.getAddress());
                row.createCell(3).setCellValue(order.isPayment() ? "Paypal" : "Cash");
                row.createCell(4).setCellValue(order.getTotal_money());
                row.createCell(5).setCellValue(order.getStatus_order().getName());
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            workbook.write(out);

            HttpHeaders headers = new HttpHeaders();
            headers.add("Content-Disposition", "attachment; filename=orders.xlsx");

            return new ResponseEntity<>(out.toByteArray(), headers, HttpStatus.OK);
        } catch (Exception e) {
            // Handle exception
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
