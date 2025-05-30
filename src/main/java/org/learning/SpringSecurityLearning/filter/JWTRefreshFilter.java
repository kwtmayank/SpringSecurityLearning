package org.learning.SpringSecurityLearning.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.learning.SpringSecurityLearning.Utils.JWTUtil;
import org.learning.SpringSecurityLearning.Utils.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTRefreshFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public JWTRefreshFilter(JWTUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!request.getServletPath().equals("/refresh-token")) {
            filterChain.doFilter(request, response);
            return;
        }

        String refreshToken = extractJwtFromRequest(request);

        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(refreshToken);
        Authentication authenticationResult = authenticationManager.authenticate(jwtAuthenticationToken);

        if (authenticationResult.isAuthenticated()) {
            String token = jwtUtil.generateToken(authenticationResult.getName(), 2);
            response.setHeader("Authorization", "Bearer " + token);
        }
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refreshToken")) {
                refreshToken = cookie.getValue();
            }
        }
        return refreshToken;
    }

}
