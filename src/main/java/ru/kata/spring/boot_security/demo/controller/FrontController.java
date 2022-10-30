package ru.kata.spring.boot_security.demo.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class FrontController {
    @GetMapping("/")
    public String MainPage() {
        return "redirect:/login";
    }
}
