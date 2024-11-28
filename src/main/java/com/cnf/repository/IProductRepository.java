package com.cnf.repository;


import com.cnf.entity.Category;
import com.cnf.entity.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;


import java.util.List;

@Repository
public interface IProductRepository extends JpaRepository<Product, Long> {
    @Query("SELECT p from Product p WHERE p.category.id = ?1 AND p.active = true")
    List<Product> getAllProductById(Long id);

    @Query("SELECT p from Product p WHERE p.active = true")
    List<Product> getAllProductActive();

    @Query("SELECT p from Product p WHERE p.active = false")
    List<Product> getAllProductNotActive();

    @Query("SELECT p from Product p where p.name like %?1% and p.active = true")
    List<Product> searchProductByNam(String keyword, Pageable pageable);

    @Query("SELECT p FROM Product p WHERE p.id = ?1")
    Product findByProId(Long id);

    Page<Product> findByCategory(Category category, Pageable pageable);
}
