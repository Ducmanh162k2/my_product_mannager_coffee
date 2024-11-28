package com.cnf.controller.client;

import com.cnf.daos.ProductDTO;
import com.cnf.entity.Product;
import com.cnf.services.ProductService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class SearchRestController {
    @Autowired
    private ProductService productService;
    @GetMapping("/search")
    public List<ProductDTO> searchProduct(@RequestParam("searchText") String searchText){
        List<Product> products = productService.searchProductByName(searchText);
        List<ProductDTO> productDTOs = convertToDTO(products);
        return productDTOs;
    }

    private List<ProductDTO> convertToDTO(List<Product> products) {
        List<ProductDTO> productDTOs = new ArrayList<>();
        for (Product product : products) {
            ProductDTO productDTO = new ProductDTO();
            productDTO.setId(product.getId());
            productDTO.setName(product.getName());
            productDTO.setImage(product.getImagesPath());
            productDTO.setDesc(product.getDescription());
            productDTO.setPrice(product.getPrice());
            productDTOs.add(productDTO);
        }
        return productDTOs;
    }
}
