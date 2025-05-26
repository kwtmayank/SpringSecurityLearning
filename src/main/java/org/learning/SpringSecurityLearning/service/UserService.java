package org.learning.SpringSecurityLearning.service;

import org.learning.SpringSecurityLearning.entity.UserAuth;
import org.learning.SpringSecurityLearning.repository.UserAuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserAuthRepository userAuthRepository;

    @Override
    public UserAuth loadUserByUsername(String username) throws UsernameNotFoundException {
        return userAuthRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    public boolean registerUser(UserAuth userAuth) {

        Optional<UserAuth> user = userAuthRepository.findByUsername(userAuth.getUsername());
        user.ifPresent(u -> {
            throw new IllegalStateException("User already exists");
        });

        userAuthRepository.save(userAuth);

        return true;
    }
}
