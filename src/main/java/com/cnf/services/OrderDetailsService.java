package com.cnf.services;

import com.cnf.entity.OrderDetails;
import com.cnf.entity.Orders;
import com.cnf.entity.Product;
import com.cnf.enums.ResultEnum;
import com.cnf.exception.CustomException;
import com.cnf.repository.IOderDetailsRepository;
import com.cnf.repository.IOrderRepository;
import com.cnf.ultils.SplitIdsUtil;
import jakarta.persistence.criteria.Predicate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class OrderDetailsService {
    @Autowired
    IOderDetailsRepository oderDetailsRepository;
    @Autowired
    IOrderRepository orderRepository;
    public List<OrderDetails> getAllOrderDetailsByOrderId(Long id){
        return oderDetailsRepository.findAllOrderDetailsByOrderId(id);
    }
    public List<Product> getTop5ProductsByRevenue() {
        Pageable pageable = PageRequest.of(0, 5);
        return oderDetailsRepository.findTop5ProductsByRevenue(pageable);
    }

//    public Page<OrderDetails> getOrderDetailsByOrderId(Long orderId, int pageNum, int pageSize) {
//        Pageable pageable = PageRequest.of(pageNum, pageSize);
//        return oderDetailsRepository.findByOrderId(orderId, pageable);
//    }

    // Phương thức để lấy danh sách chi tiết đơn hàng theo mã đơn hàng và phân trang
    public Page<OrderDetails> getOrderDetailsByOrderId(Long orderCode, Pageable pageable) {
        return oderDetailsRepository.findByOrderId(orderCode, pageable);
    }

    public Page<OrderDetails> findPage(Pageable pageable, OrderDetails filter) {
        // Sử dụng Specification để áp dụng các điều kiện lọc
        return oderDetailsRepository.findAll(createSpecification(filter), pageable);
    }

    private Specification<OrderDetails> createSpecification(OrderDetails filter) {
        return (root, query, criteriaBuilder) -> {
            Predicate predicate = criteriaBuilder.conjunction();

            if (filter.getId() != null) {
                predicate = criteriaBuilder.and(predicate, criteriaBuilder.equal(root.get("id"), filter.getId()));
            }
            // Thêm các điều kiện khác nếu cần

            return predicate;
        };
    }

    public void deleteByIds(String strIds) {
        List<Long> idList = SplitIdsUtil.splitStrIds(strIds);

        // Tính toán giá trị bị trừ
        Double minusPrice = oderDetailsRepository.countPriceByOdIds(idList);

        // Tìm chi tiết đơn hàng đầu tiên
        OrderDetails orderDetail = oderDetailsRepository.findById(idList.get(0))
                .orElseThrow(() -> new CustomException(ResultEnum.UNKNOWN_ERROR));
        Long orderId = orderDetail.getOrders().getId();

        // Cập nhật tổng giá trị đơn hàng
        Orders findOrder = orderRepository.findById(orderId)
                .orElseThrow(() -> new CustomException(ResultEnum.UNKNOWN_ERROR));

        findOrder.setTotal_money(findOrder.getTotal_money() - minusPrice);
        findOrder.setDate_purchase(new Date());
        orderRepository.save(findOrder);

        // Xóa các chi tiết đơn hàng
        int effect = oderDetailsRepository.deleteByIds(idList);
        if (effect <= 0) {
            throw new CustomException(ResultEnum.DEL_DB_FAIL);
        }
    }




}
