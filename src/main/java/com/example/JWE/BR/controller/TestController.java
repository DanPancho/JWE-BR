package com.example.JWE.BR.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/hola")
    public String hola(){
        return "HOLA MUNDO";
    }
}
