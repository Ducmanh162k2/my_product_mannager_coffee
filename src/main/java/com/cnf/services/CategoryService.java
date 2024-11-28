package com.cnf.services;

import com.cnf.entity.Category;
import com.cnf.repository.ICategoryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class CategoryService {
    @Autowired
    private ICategoryRepository categoryRepository;
    public List<Category> getAllCategories(){
        return categoryRepository.findAll();
    }
    public Optional<Category> getCategoryById(Long id){
        return categoryRepository.findById(id);
    }
    public void addCategory(Category category){
        categoryRepository.save(category);
    }
    public void updateCategory(Category category){
        Category existingCategory = categoryRepository.findById(category.getId()).orElse(null);
        existingCategory.setName(category.getName());
        existingCategory.setDescription(category.getDescription());
        categoryRepository.save(existingCategory);
    }
    public void deleteCategoryById(Long id){
        categoryRepository.deleteById(id);
    }
    public Page<Category> findPaginated(int pageNo, int pageSize) {
        Pageable pageable = PageRequest.of(pageNo - 1, pageSize);
        return this.categoryRepository.findAll(pageable);
    }

    public Category findCategoryById(Long id){
        return categoryRepository.findById(id).orElse(null);
    }
}
