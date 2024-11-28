package com.cnf.repository;

import com.cnf.entity.Orders;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface IOrderRepository extends JpaRepository<Orders, Long> {
    @Query("SELECT o from Orders o WHERE o.user.id = ?1")
    List<Orders> findAllOrderByUserId(Long userId);

    @Query("SELECT o FROM Orders o WHERE "
            + "(:search IS NULL OR o.address LIKE %:search% OR CAST(o.id AS string) LIKE %:search%) "
            + "AND (:status IS NULL OR o.status_order.id = :status) "
            + "AND (:startDate IS NULL OR o.date_purchase >= :startDate) "
            + "AND (:endDate IS NULL OR o.date_purchase <= :endDate)")
    List<Orders> findAllByCriteria(@Param("search") String search,
                                  @Param("status") Integer status,
                                  @Param("startDate") LocalDate startDate,
                                  @Param("endDate") LocalDate endDate);

}
