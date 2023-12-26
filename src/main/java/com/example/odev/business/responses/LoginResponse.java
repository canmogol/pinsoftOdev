package com.example.odev.business.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {

    private String username;
    private String email;
    private String token;

    public LoginResponse(String username, String token) {
        this.username = username;
        this.token = token;
    }
}
