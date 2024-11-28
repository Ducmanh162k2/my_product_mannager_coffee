package com.cnf.validatiors;


import com.cnf.entity.OrderDetails;
import com.cnf.entity.Product;
import com.cnf.entity.User;
import com.cnf.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.security.Principal;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserAuthValidator {

    private final UserService userService;

    public Optional<User> authenticate(Principal principal) {
        if (principal == null) {
            return null;
        }
        return userService.findByUsername1(principal.getName());
    }

    public User getCurrentUser(Principal principal) {
        if (principal == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Không có thông tin người dùng được xác thực.");
        }
        return userService.findByUsername1(principal.getName())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Không tìm thấy người dùng."));
    }
    public User getCurrentUserByUsername(String username) {
        return userService.findByUsername1(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Không tìm thấy người dùng."));
    }

    public User getCurrentUserByUserID(Long sellerID) {
        return userService.findByUserid1(sellerID)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Không tìm thấy người dùng."));
    }


}
