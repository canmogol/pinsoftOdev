package com.example.odev.business.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProductRequest {
    private MultipartFile address;
    private String name;
    private String explanation;
    private Double price;
    private Long category_id;
}
