package com.cnf.repository;

import com.cnf.entity.OrderDetails;
import com.cnf.entity.Orders;
import com.cnf.entity.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IOderDetailsRepository extends JpaRepository<OrderDetails, Long> {
    @Query("SELECT o from OrderDetails o WHERE o.orders.id = ?1")
    List<OrderDetails> findAllOrderDetailsByOrderId(Long id);

    @Query("SELECT od.product, SUM(od.total_money) AS revenue " +
            "FROM OrderDetails od " +
            "GROUP BY od.product " +
            "ORDER BY revenue DESC")
    List<Product> findTop5ProductsByRevenue(Pageable pageable);


    @Query("SELECT SUM(od.quantity * p.price) FROM OrderDetails od JOIN od.product p WHERE od.id IN :odIds")
    Double countPriceByOdIds(List<Long> odIds);

    @Modifying
    @Query("UPDATE OrderDetails od SET od.del = 1 WHERE od.id IN :odIdList")
    int deleteByIds(List<Long> odIdList);


    Page<OrderDetails> findAll(Specification<OrderDetails> specification, Pageable pageable);
//    @Query("SELECT od FROM OrderDetails od WHERE od.orders.id = :orderId")
//    Page<OrderDetails> findByOrderId(@Param("orderId") Long orderId, Pageable pageable);

    // Query để lấy danh sách chi tiết đơn hàng theo mã đơn hàng và phân trang
    @Query("SELECT od FROM OrderDetails od WHERE od.orders.id = :orderCode")
    Page<OrderDetails> findByOrderId(Long orderCode, Pageable pageable);
}
