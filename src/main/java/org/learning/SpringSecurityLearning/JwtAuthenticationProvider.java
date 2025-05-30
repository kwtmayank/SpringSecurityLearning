package org.learning.SpringSecurityLearning;

import org.learning.SpringSecurityLearning.Utils.JWTUtil;
import org.learning.SpringSecurityLearning.Utils.JwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class JwtAuthenticationProvider implements AuthenticationProvider {

    private JWTUtil jwtUtil;
    private UserDetailsService userDetailsService;

    public JwtAuthenticationProvider(JWTUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token =((JwtAuthenticationToken) authentication).getToken();

        String Username = jwtUtil.validateAndExtractUsername(token);
        if (Username == null) {
            throw new BadCredentialsException("Invalid Token");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(Username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
