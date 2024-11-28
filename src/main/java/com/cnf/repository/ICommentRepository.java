package com.cnf.repository;

import com.cnf.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ICommentRepository extends JpaRepository<Comment, Long> {
    @Query("SELECT c from Comment c WHERE c.blog.id = ?1")
    List<Comment> getAllCommentByBlogId(Long id);

}
