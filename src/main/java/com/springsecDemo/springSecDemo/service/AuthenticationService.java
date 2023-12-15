package com.springsecDemo.springSecDemo.service;

import com.springsecDemo.springSecDemo.config.JwtUtil;
import com.springsecDemo.springSecDemo.dto.AuthenticationRequest;
import com.springsecDemo.springSecDemo.dto.AuthenticationResponse;
import com.springsecDemo.springSecDemo.dto.RegisterRequest;
import com.springsecDemo.springSecDemo.token.Token;
import com.springsecDemo.springSecDemo.token.TokenRepository;
import com.springsecDemo.springSecDemo.token.TokenType;
import com.springsecDemo.springSecDemo.user.Role;
import com.springsecDemo.springSecDemo.user.User;
import com.springsecDemo.springSecDemo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private  final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(()->new UsernameNotFoundException("User not found"));
        var jwtToken = jwtUtil.generateToken(user);
        revokeAllUserToken(user);
        saveUserToken(user,jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedUser =userRepository.save(user);
        var jwtToken = jwtUtil.generateToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    private void saveUserToken(User savedUser, String jwtToken) {
        var token = Token.builder()
                .user(savedUser)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserToken(User user){
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t->{
            t.setRevoked(true);
            t.setExpired(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
}
