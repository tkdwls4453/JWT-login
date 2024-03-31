package com.example.jwtlogin.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String main(){
        return "Main Controller Access";
    }

    @GetMapping("/admin")
    public String admin(){
        return "Admin Controller Access";
    }
}
