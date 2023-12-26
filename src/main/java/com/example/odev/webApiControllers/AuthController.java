package com.example.odev.webApiControllers;

import com.example.odev.business.auth.JwtUtil;
import com.example.odev.business.requests.LoginRequest;
import com.example.odev.business.responses.ErrorResponse;
import com.example.odev.business.responses.LoginResponse;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtil jwtUtil;

    @ResponseBody
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public ResponseEntity login(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
            String username = authentication.getName();
            List<String> authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
            String token = jwtUtil.createToken(username, authorities);
            LoginResponse loginResponse = new LoginResponse(username, token);

            return ResponseEntity.ok(loginResponse);
        } catch (BadCredentialsException badCredentialsException) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, "Hatalı şifre ya da kullanıcı adı");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (Exception exceptionn) {
            ErrorResponse errorResponse = new ErrorResponse(HttpStatus.BAD_REQUEST, exceptionn.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

}
