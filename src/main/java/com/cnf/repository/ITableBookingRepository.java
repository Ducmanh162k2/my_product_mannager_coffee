package com.cnf.repository;


import com.cnf.entity.TableBooking;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ITableBookingRepository extends JpaRepository<TableBooking, Long> {
    //List<TableBooking> findByTableCode(String tableCode);

    @Query("SELECT d FROM TableBooking d WHERE d.tableCode = ?1 ")
    TableBooking findByTableCode(String deskCode);

    List<TableBooking> findByPeopleCount(Integer peopleCount);

    List<TableBooking> findByStatus(Integer status);

    List<TableBooking> findByDel(Integer del);

    @Transactional
    @Modifying
    @Query("UPDATE TableBooking d SET d.del = 1 WHERE d.tableId IN :ids")
    int deleteByIds(List<Long> ids);

    @Query("SELECT t FROM TableBooking t WHERE t.tableId = ?1 AND t.del = 0")
    TableBooking findTableBookingByTableId(Long tableId);
}