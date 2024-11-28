package com.cnf.repository;

import com.cnf.entity.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IImportDataRepository extends JpaRepository<Product,Long> {

}
