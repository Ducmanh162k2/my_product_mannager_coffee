package com.cnf.daos;

import lombok.Data;

@Data
public class ProductDTO1 {
    private Long id;
    private String name;
    private String img;
    private CategoryDTO category; // Liên kết tới một DTO khác nếu cần
    private double price;
}
