
package com.cnf.services;

import com.cnf.entity.TableBooking;
import com.cnf.enums.ResultEnum;
import com.cnf.exception.CustomException;
import com.cnf.repository.ITableBookingRepository;
import com.cnf.ultils.SplitIdsUtil;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@Transactional
public class TableBookingService {
    @Autowired
    private ITableBookingRepository bookingRepository;
    public Page<TableBooking> findPaginated(int pageNo, int pageSize) {
        Pageable pageable = PageRequest.of(pageNo - 1, pageSize);
        return this.bookingRepository.findAll(pageable);
    }

    public TableBooking findById(Long id) {
        return bookingRepository.findTableBookingByTableId(id);
    }


    public void insert(String desk) {
        TableBooking findDesk = bookingRepository.findByTableCode(desk);
        if(findDesk!=null){
            throw new CustomException(ResultEnum.DESK_CODE_IS_EXIST);
        }
        LocalDateTime now = LocalDateTime.now();
        findDesk.setCreateTime(now);
        bookingRepository.save(findDesk);
    }

    public void update(String desk) {
        TableBooking findDesk = bookingRepository.findByTableCode(desk);
        if(findDesk!=null){
            throw new CustomException(ResultEnum.DESK_CODE_IS_EXIST);
        }
        LocalDateTime now = LocalDateTime.now();
        findDesk.setModifyTime(now);
        bookingRepository.save(findDesk);
    }


    public void deleteByIds(String strIds) {
        List<Long> idList = SplitIdsUtil.splitStrIds(strIds);
        int effect =  bookingRepository.deleteByIds(idList);
        if(effect<=0){
            throw new CustomException(ResultEnum.DEL_DB_FAIL);
        }
    }

    public TableBooking findByTableCode(String desk) {
        return bookingRepository.findByTableCode(desk);
    }

    public void booking(String desk) {
        TableBooking findDesk =  bookingRepository.findByTableCode(desk);
        if(findDesk==null){
            throw new CustomException(ResultEnum.DESK_CODE_NO_EXIST);
        }
        if(findDesk.getStatus()==1||findDesk.getStatus()==2){
            throw new CustomException(ResultEnum.DESK_CODE_NO_IDLE);
        }
        //
        findDesk.setStatus(1);
        bookingRepository.save(findDesk);
    }


    public void logout(String desk){
        TableBooking findDesk =  bookingRepository.findByTableCode(desk);
        findDesk.setStatus(0);
        bookingRepository.save(findDesk);
    }
}
