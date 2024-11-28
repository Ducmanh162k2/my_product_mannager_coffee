package com.cnf.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@Table(name = "role")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(length = 50, nullable = false)
    @Size(max = 50, message = "Name must be less than 50 characters")
    @NotBlank(message = "Name is required")
    private String name;
    @Column(length = 250)
    @Size(max = 50, message = "Name must be less than 50 characters")
    @NotBlank(message = "Description is required")
    private String description;
    @ManyToMany(mappedBy = "roles")
    private Set<User> users = new HashSet<>();
}
