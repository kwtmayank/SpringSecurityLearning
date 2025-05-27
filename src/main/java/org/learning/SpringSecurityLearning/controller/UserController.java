package org.learning.SpringSecurityLearning.controller;

import org.learning.SpringSecurityLearning.entity.UserAuth;
import org.learning.SpringSecurityLearning.model.UserDTO;
import org.learning.SpringSecurityLearning.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder encoder;


    @PostMapping("/register")
    public String saveUser(@RequestBody UserDTO userRequest) {
        UserAuth userAuth = new UserAuth();
        userAuth.setUsername(userRequest.getUsername());
        userAuth.setPassword(encoder.encode(userRequest.getPassword()));
        userAuth.setRole(userRequest.getRole());
         boolean result = userService.registerUser(userAuth);

        if (result) {
            return "User registered successfully";
        } else {
            return "User registration failed";
        }
    }

    @GetMapping("/getUser")
    public String getUser() {
        return "Hello from User";
    }
}
