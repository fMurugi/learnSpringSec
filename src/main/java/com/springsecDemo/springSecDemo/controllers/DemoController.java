package com.springsecDemo.springSecDemo.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/demo-controller")
public class DemoController {
    @GetMapping
    public ResponseEntity<String> hey(){
        return ResponseEntity.ok("hellloo you made it");
    }
}