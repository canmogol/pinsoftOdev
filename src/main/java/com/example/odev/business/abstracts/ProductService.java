package com.example.odev.business.abstracts;

import com.example.odev.business.responses.GetAllProducts;
import com.example.odev.business.responses.GetProductsDetails;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface ProductService {


    List<GetAllProducts> getAll();

    List<GetProductsDetails> findAll();

    void saveProductToDB(MultipartFile address, String name, String explanation, Double price, Long category_id);


}
