package com.example.odev.webApiControllers;

import com.example.odev.business.abstracts.ProductService;
import com.example.odev.business.abstracts.UserService;
import com.example.odev.business.concretes.ProductManager;
import com.example.odev.business.responses.GetAllProducts;
import com.example.odev.business.responses.GetProductsDetails;
import com.example.odev.business.responses.ProductRequest;
import com.example.odev.business.responses.UserRequest;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/products")
@AllArgsConstructor
@NoArgsConstructor
public class ProductsControllers {

    @Autowired
    private ProductService productService;

    @Autowired
    private ProductManager productManager;

    @Autowired
    private UserService userService;

    @GetMapping("/getAll")
    public List<GetAllProducts> getAll() {
        return productService.getAll();
    }

    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/getProductDetails")
    public List<GetProductsDetails> findAll() {
        return productService.findAll();
    }

    @PostMapping("/addP")
    public String saveProduct(@RequestBody ProductRequest request) {
        productService.saveProductToDB(request.getAddress(), request.getName(), request.getExplanation(), request.getPrice(), request.getCategory_id());
        return "redirect:/listProduct.html";
    }

    @PostMapping("/register")
    public String showRegistrationForm(@RequestBody UserRequest request) {
        // create model object to store form data
        userService.saveUserToDB(request.getUsername(), request.getEmail(), request.getPassword());
        return "basarili";
    }

    @GetMapping("/search")
    public ResponseEntity<List<GetProductsDetails>> searchProducts(@RequestParam String name) {
        List<GetProductsDetails> searchResults = productManager.searchProducts(name);
        return new ResponseEntity<>(searchResults, HttpStatus.OK);
    }
}
