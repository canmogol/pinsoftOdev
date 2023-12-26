package com.example.odev.business.abstracts;

import com.example.odev.business.responses.GetAllCategories;

import java.util.List;

public interface CategoryService {
    List<GetAllCategories> getAll();
}
