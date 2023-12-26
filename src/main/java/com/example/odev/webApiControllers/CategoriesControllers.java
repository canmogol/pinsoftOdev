package com.example.odev.webApiControllers;

import com.example.odev.business.abstracts.CategoryService;
import com.example.odev.business.responses.GetAllCategories;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/categories")
@AllArgsConstructor
@NoArgsConstructor
public class CategoriesControllers {

    @Autowired
    private CategoryService categoryService;

    @GetMapping("/getAll")
    public List<GetAllCategories> getAll() {
        return categoryService.getAll();
    }
}
