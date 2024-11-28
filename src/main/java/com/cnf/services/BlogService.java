package com.cnf.services;

import com.cnf.entity.Blog;
import com.cnf.entity.User;
import com.cnf.repository.IBlogRepository;
import com.cnf.ultils.FileUploadUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Date;
import java.util.List;

@Service
public class BlogService {
    @Autowired
    private IBlogRepository blogRepository;
    @Autowired
    private UserService userService;
    public List<Blog> getAllBlogs(){
        return blogRepository.findAll();
    }
    public List<Blog> getRelatedBlogs(){
        Pageable pageable = PageRequest.of(0, 2); // Page number starts from 0
        return blogRepository.findAll(pageable).getContent();
    }
    public Blog getBlogById(Long id){
        return blogRepository.findById(id).orElseThrow();
    }
    public void addBlog(Blog blog,String description, MultipartFile multipartFile) throws IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        User user = userService.getUserbyUserName(username);
        String fileName = StringUtils.cleanPath(multipartFile.getOriginalFilename());
        Date date = new Date();

        blog.setBackgroundImg(fileName);
        blog.setUser(user);
        blog.setDateTime(date);
        blog.setDescription(description);
        Blog saveBlog = blogRepository.save(blog);
        String upLoadDir = "blog-images/" + saveBlog.getId();
        FileUploadUtil.saveFile(upLoadDir, fileName, multipartFile);
       blogRepository.save(blog);
    }
    public void updateBlog(Blog blog, String description, MultipartFile multipartFile) throws IOException{
        Blog existingBlog = blogRepository.findById(blog.getId()).orElseThrow();

        existingBlog.setName(blog.getName());
        existingBlog.setDescription(description);
        existingBlog.setDateTime(blog.getDateTime());

        if(multipartFile != null && !multipartFile.isEmpty()){
            String fileName = StringUtils.cleanPath(multipartFile.getOriginalFilename());
            existingBlog.setBackgroundImg(fileName);
            String upLoadDir = "blog-images/" + blog.getId();
            FileUploadUtil.saveFile(upLoadDir, fileName, multipartFile);
        }
        blogRepository.save(existingBlog);
    }
    public void deleteBlogById(Long id){
        blogRepository.deleteById(id);
    }
}
