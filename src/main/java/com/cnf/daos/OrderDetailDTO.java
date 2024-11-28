package com.cnf.daos;


import lombok.Data;

@Data
public class OrderDetailDTO {
    private Long id;
    private int quantity;
    private double total_money;
    private Integer status ;
    private ProductDTO1 product;
    private Integer del;
}
