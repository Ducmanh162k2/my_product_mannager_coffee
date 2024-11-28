package com.cnf.repository;

import com.cnf.entity.StatusOrder;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IStatusOrderRepository extends JpaRepository<StatusOrder, Long> {
}
