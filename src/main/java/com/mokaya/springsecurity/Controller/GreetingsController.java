package com.mokaya.springsecurity.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingsController {

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello World!";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/welcome")
    public String customerEndpoint() {
        return "Welcome User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "I'm an admin!";
    }
}
