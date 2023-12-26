package com.example.odev.business.concretes;

import com.example.odev.Entity.Category;
import com.example.odev.Repository.CategoryRepository;
import com.example.odev.business.abstracts.CategoryService;
import com.example.odev.business.responses.GetAllCategories;
import com.example.odev.mappers.ModelMapperService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@NoArgsConstructor
public class CategoryManager implements CategoryService {

    @Autowired
    private CategoryRepository categoryRepository;

    @Autowired
    private ModelMapperService modelMapperService;


    @Override
    public List<GetAllCategories> getAll() {
        List<Category> categories = categoryRepository.findAll();
        List<GetAllCategories> getresponse = categories.stream()
                .map(category -> this.modelMapperService.forResponse()
                        .map(category, GetAllCategories.class)).collect(Collectors.toList());
        return getresponse;
    }
}
