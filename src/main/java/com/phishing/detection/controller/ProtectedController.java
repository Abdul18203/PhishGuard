package com.phishing.detection.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProtectedController {

    @GetMapping("/api/test/protected")
    public String protectedEndpoint() {
        return "JWT authentication is working!";
    }
}