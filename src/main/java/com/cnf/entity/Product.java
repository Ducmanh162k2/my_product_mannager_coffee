package com.cnf.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "product")
@AllArgsConstructor
@NoArgsConstructor
public class Product {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @NotBlank(message = "Name is required")
    private String name;
    @NotBlank(message = "Description is required")
    @Column(columnDefinition = "LONGTEXT")
    private String description;
    @Min(value = 1, message = "Rent should be greater than or equal to 1")
    private double price;
    private float quantity;
    private int discount;
    @Column(name = "active", columnDefinition = "BIT(1)")
    private Boolean active;
    private String img;
    private float weight;


    public String getImagesPath() {
        if (img == null || id == null) return null;
        return  File.separator + "client_assets" + File.separator + "product-images" + File.separator + id + File.separator + img;
    }
    @ManyToOne
    @JoinColumn(name = "category_id")
    private Category category;
    @OneToMany(mappedBy = "product")
    @JsonIgnore
    private List<OrderDetails> orderDetails = new ArrayList<>();
    @OneToMany(mappedBy = "product", fetch = FetchType.EAGER)
    @JsonIgnore
    private List<Comment> comments;
    public int getTotalComments(){
        return comments.size();
    }
    public int getAverageRating(){
        int totalRating = 0;

        for(Comment comment : comments){
            totalRating += comment.getRating_value();
        }

        if(getTotalComments() == 0)
            return 0;
        else
            return totalRating / getTotalComments();
    }
}
