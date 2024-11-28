package com.cnf.daos;

import lombok.Data;

import java.util.Date;
import java.util.List;


@Data
public class OrderDTO1 {
    private Long id;
    private Date date_purchase;
    private String note;
    private String address;
    private double total_money;
    private boolean payment;
    private String status_name;
    private Long status_id;
    private List<OrderDetailDTO> orderDetails;
}
