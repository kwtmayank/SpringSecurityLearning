package org.learning.SpringSecurityLearning.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/order")
public class OrderController {

    @GetMapping("/delete")
    @PreAuthorize("hasAuthority('ADMIN') AND hasAuthority('DELETE_ORDER')")
    public String order() {
        return "Order Deleted";
    }

    @GetMapping("/update")
    @PreAuthorize("hasRole('USER')")
    public String update() {
        return "Order Updated";
    }
}
