package com.cnf.services;

import com.cnf.entity.Blog;
import com.cnf.entity.Comment;
import com.cnf.entity.Product;
import com.cnf.entity.User;
import com.cnf.repository.ICommentRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class CommentService {
    @Autowired
    private ICommentRepository commentRepository;
    public List<Comment> getAllComments(){
        return commentRepository.findAll();
    }
    public List<Comment> getAllCommentsByBlogId(Long id){
        return commentRepository.getAllCommentByBlogId(id);
    }
    public Optional<Comment> getCommentById(Long id){
        return commentRepository.findById(id);
    }
    public void addComment(User user, Product product, String text, int rate){
        Date date = new Date();
        Comment comment = new Comment();
        comment.setUser(user);
        comment.setProduct(product);
        comment.setComment_text(text);
        comment.setRating_value(rate);
        comment.setTimestamp(date);
        commentRepository.save(comment);
    }
    public void addCommentForBlog(User user, Blog blog, String text){
        Date date = new Date();
        Comment comment = new Comment();
        comment.setUser(user);
        comment.setBlog(blog);
        comment.setComment_text(text);
        comment.setTimestamp(date);
        commentRepository.save(comment);
    }
    public void deleteCommentById(Long id){
        commentRepository.deleteById(id);
    }

}
