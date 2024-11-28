package com.cnf.repository;

import com.cnf.entity.User;
import jakarta.transaction.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IUserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    @Query("SELECT u from User u WHERE u.username = ?1")
    User findEmail(String email);
    @Query("SELECT u from User u WHERE u.username = ?1")
    User findByUsername(String username);
    @Modifying
    @Transactional
    @Query(value = "INSERT INTO user_role (user_id, role_id)" + "VALUES (?1, ?2)" , nativeQuery = true)
    void addRoleToUser (Long userId , Long roleId);

    @Query("SELECT u.id FROM User u WHERE u.username = ?1")
    Long getUserIdByUsername (String username);

    @Query("SELECT u FROM User u WHERE u.id = ?1")
    User getUserByUserID (Long userID);

    @Query (value = "SELECT r.name FROM role r INNER JOIN user_role ur " +
            "ON r.id = ur.role_id WHERE ur.user_id = ?1", nativeQuery= true)
    String[] getRolesOfUser (Long userId);

    @Query("SELECT u from User u WHERE u.username = ?1")
    Optional<User> findByUsername1(String username);

    @Query("SELECT u FROM User u WHERE u.id = ?1")
    Optional<User> getUserByUserID1 (Long userID);


    @Query(
            value = "\n" +
                    "SELECT * \n" +
                    "FROM User u \n" +
                    "INNER JOIN user_role ur ON u.id = ur.user_id\n" +
                    "INNER JOIN role r ON r.id = ur.role_id",
            nativeQuery = true
    )
    List<User> getAllUser() ;

    @Query(
            value = "SELECT u.* FROM User u INNER JOIN user_role ur ON u.id = ur.user_id WHERE ur.role_id = 3",
            countQuery = "SELECT count(*) FROM User u INNER JOIN user_role ur ON u.id = ur.user_id WHERE ur.role_id = 3",
            nativeQuery = true
    )
    Page<User> findStaffUser(Pageable pageable);

    @Query(
            value = "SELECT u.* FROM User u INNER JOIN user_role ur ON u.id = ur.user_id WHERE ur.role_id = 3",
            nativeQuery = true
    )
    List<User> findAllStaff();

    @Query(
            value = "SELECT u.* FROM User u INNER JOIN user_role ur ON u.id = ur.user_id WHERE ur.role_id = 2",
            nativeQuery = true
    )
    List<User> findAllUser();



    @Query("SELECT u FROM User u WHERE u.active = true")
    List<User> getAllActiveUser();

    @Query("SELECT u FROM User u WHERE u.active = false")
    List<User> getAllNotActiveUser();


}
