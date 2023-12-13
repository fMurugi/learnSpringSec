package com.springsecDemo.springSecDemo.controllers;

import com.springsecDemo.springSecDemo.config.JwtUtil;
import com.springsecDemo.springSecDemo.dao.UserDao;
import com.springsecDemo.springSecDemo.dto.AuthenticationRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
private  final AuthenticationManager authenticationManager;
private final UserDao userDao;
private final JwtUtil jwtUtil;

    // public AuthController(AuthenticationManager authenticationManager, UserDao userDao, JwtUtil jwtUtil) {
    //     this.authenticationManager = authenticationManager;
    //     this.userDao = userDao;
    //     this.jwtUtil = jwtUtil;
    // }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticate(
            @RequestBody AuthenticationRequest request
    ){
       
        UserDetails user = userDao.findUserByEmail(request.getEmail());
        if(user!=null){
            Authentication authentication =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword())
        );
            // SecurityContextHolder.getContext().setAuthentication(authentication);
            return ResponseEntity.ok( jwtUtil.generateToken(user));
        }
        return ResponseEntity.status(400).body("Bad request");
    }
}
