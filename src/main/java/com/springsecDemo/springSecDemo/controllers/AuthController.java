package com.springsecDemo.springSecDemo.controllers;

import com.springsecDemo.springSecDemo.config.JwtUtil;
import com.springsecDemo.springSecDemo.dao.UserDao;
import com.springsecDemo.springSecDemo.dto.AuthenticationRequest;
import com.springsecDemo.springSecDemo.dto.AuthenticationResponse;
import com.springsecDemo.springSecDemo.dto.RegisterRequest;
import com.springsecDemo.springSecDemo.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
private  final AuthenticationManager authenticationManager;
private final UserDao userDao;
private final JwtUtil jwtUtil;
private final AuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(authenticationService.authenticate(request));

    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ){
        return ResponseEntity.ok(authenticationService.register(request));
    }

//    @PostMapping("/logout")
//    public ResponseEntity<String> logout(){
//
//    }
}
