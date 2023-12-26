package com.example.odev.business.concretes;

import com.example.odev.Entity.User;
import com.example.odev.Repository.UserRepository;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import static java.util.Objects.isNull;

@Service
@AllArgsConstructor
@NoArgsConstructor
public class UserManager implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);
        if (isNull(user)) {
            throw new UsernameNotFoundException("User not found");
        }
        UserDetails userDetails = org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole().getName().toUpperCase())
                .build();

        /*
        userDetails = org.springframework.security.core.userdetails.User
        [
            Username=admin,
            Password=[PROTECTED],
            Enabled=true,
            AccountNonExpired=true,
            CredentialsNonExpired=true,
            AccountNonLocked=true,
            Granted Authorities=
                    [
                        ROLE_admin
                    ]
        ]
         */
        return userDetails;
    }

}
