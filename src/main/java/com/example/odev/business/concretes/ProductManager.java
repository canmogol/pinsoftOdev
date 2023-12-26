package com.example.odev.business.concretes;

import com.example.odev.Entity.Category;
import com.example.odev.Entity.Product;
import com.example.odev.Repository.CategoryRepository;
import com.example.odev.Repository.ProductRepository;
import com.example.odev.business.abstracts.ProductService;
import com.example.odev.business.responses.GetAllProducts;
import com.example.odev.business.responses.GetProductsDetails;
import com.example.odev.mappers.ModelMapperService;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@NoArgsConstructor
public class ProductManager implements ProductService {

    @Autowired
    private ProductRepository productRepository;

    @Autowired
    private CategoryRepository categoryRepository;

    public void saveProductToDB(MultipartFile address, String name, String explanation, Double price, Long category_id) {
        Product p = new Product();
        String fileName = address != null ? StringUtils.cleanPath(address.getOriginalFilename()) : null;

        try {
            if (address != null) {
                p.setAddress(Base64.getEncoder().encodeToString(address.getBytes()));
            } else {
                // Adres null ise özel bir değer veya boş bir değer atayabilirsiniz.
                p.setAddress(""); // Veya null değeri kabul edilebilirse: p.setAddress(null);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        p.setExplanation(explanation);

        Category category = categoryRepository.findById(category_id)
                .orElseThrow(() -> new EntityNotFoundException());

        p.setCategory(category);
        p.setName(name);
        p.setPrice(price);
        productRepository.save(p);
    }


    @Autowired
    private ModelMapperService modelMapperService;

    @Override
    public List<GetAllProducts> getAll() {
        List<Product> products = productRepository.findAll();
        List<GetAllProducts> getAllProducts = products.stream()
                .map(product -> this.modelMapperService.forResponse()
                        .map(product, GetAllProducts.class)).collect(Collectors.toList());
        return getAllProducts;
    }

    @Override
    public List<GetProductsDetails> findAll() {
        List<Product> products = productRepository.findAll();
        List<GetProductsDetails> getProductsDetails = products.stream()
                .map(product -> this.modelMapperService.forResponse()
                        .map(product, GetProductsDetails.class)).collect(Collectors.toList());
        return getProductsDetails;
    }

    public List<GetProductsDetails> searchProducts(String name) {
        List<Product> products = productRepository.findAll();
        List<GetProductsDetails> matchingProducts = products.stream()
                .filter(product -> product.getName().toLowerCase().contains(name.toLowerCase()) ||
                        product.getCategory().getName().toLowerCase().contains(name.toLowerCase()))
                .map(product -> modelMapperService.forResponse().map(product, GetProductsDetails.class))
                .collect(Collectors.toList());

        return matchingProducts;
    }

}
