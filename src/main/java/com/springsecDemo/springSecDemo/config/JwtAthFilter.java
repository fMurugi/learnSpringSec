package com.springsecDemo.springSecDemo.config;

import com.springsecDemo.springSecDemo.dao.UserDao;
import com.springsecDemo.springSecDemo.token.TokenRepository;
import com.springsecDemo.springSecDemo.user.User;
import com.springsecDemo.springSecDemo.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Component
@RequiredArgsConstructor
public class JwtAthFilter extends OncePerRequestFilter {
//    private final UserDao userDao;
    private  final JwtUtil jwtUtil;
//    private final UserRepository userRepository;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader(AUTHORIZATION);
        final String userEmail;
        final String jwtToken;

        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        jwtToken = authHeader.substring(7);
        userEmail =jwtUtil.extractUsername(jwtToken);

//        if(userEmail !=null && SecurityContextHolder.getContext().getAuthentication()==null){
//            UserDetails userDetails = userDao.findUserByEmail(userEmail);
//            if(jwtUtil.validateToken(jwtToken,userDetails)){
//                UsernamePasswordAuthenticationToken authToken =
//                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
//                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                SecurityContextHolder.getContext().setAuthentication(authToken);
//            }
//        }

        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            var isTokenValid = tokenRepository.findByToken(jwtToken)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            if(jwtUtil.validateToken(jwtToken,userDetails) && isTokenValid){
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }


}
