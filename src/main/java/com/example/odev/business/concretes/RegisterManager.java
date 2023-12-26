package com.example.odev.business.concretes;

import com.example.odev.Entity.User;
import com.example.odev.Repository.RoleRepository;
import com.example.odev.Repository.UserRepository;
import com.example.odev.business.abstracts.UserService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@AllArgsConstructor
@NoArgsConstructor
@Service

public class RegisterManager implements UserService {
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    public void saveUserToDB(String username, String email, String password) {
        User u = new User();
        u.setUsername(username);
        u.setEmail(email);
        // encrypt the password using spring security
        u.setPassword(password);
        u.setRole(roleRepository.findById(1L).get());
        userRepository.save(u);
    }
}
