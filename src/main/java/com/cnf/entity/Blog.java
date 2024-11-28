package com.cnf.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@Getter
@Setter
@Entity
@Table(name = "blog")
@AllArgsConstructor
@NoArgsConstructor
public class Blog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Name is required")
    private String name;

    @NotBlank(message = "Description is required")
    @Column(columnDefinition = "LONGTEXT")
    private String description;

    private String backgroundImg;

    private Date dateTime;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id")
    private User user;

    @OneToMany(mappedBy = "blog", fetch = FetchType.EAGER)
    @JsonIgnore
    private List<Comment> comments;

    public int getTotalComments(){
        return comments.size();
    }

    public String getImagesPath(){
        if(backgroundImg == null || id == null) return null;
        return "/blog-images/" + id + "/" + backgroundImg;
    }
}
