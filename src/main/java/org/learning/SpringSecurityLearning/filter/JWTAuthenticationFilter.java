package org.learning.SpringSecurityLearning.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.learning.SpringSecurityLearning.Utils.JWTUtil;
import org.learning.SpringSecurityLearning.model.LoginRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private AuthenticationManager authenticationManager;
    private JWTUtil jwtUtil;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

//    @Override
//    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//        String servletPath = request.getServletPath();
//        return servletPath.equals("/user/register") || servletPath.equals("/generate-token");
//    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!request.getServletPath().equals("/generate-token")) {
            filterChain.doFilter(request, response);
            return;
        }


        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);

        if(authentication.isAuthenticated()) {
            String token = jwtUtil.generateToken(username, 5);
            response.setHeader("Authorization", "Bearer " + token);
            String refreshToken = jwtUtil.generateToken(username, 7*24*60);
            Cookie cookie = new Cookie("refreshToken", refreshToken);
            cookie.setMaxAge(7 * 24 * 60 * 60);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            cookie.setPath("/refresh-token");
            response.addCookie(cookie);
        }
    }
}
