package org.learning.SpringSecurityLearning.Utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JWTUtil {
    private static final String SECRET_KEY = String.valueOf(Keys.secretKeyFor(SignatureAlgorithm.HS256));;
    private static final Key KEY = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));

    public String generateToken(String username, long expiryInMinutes) {
        return Jwts.builder().subject(username).expiration(new Date(System.currentTimeMillis() + expiryInMinutes * 60 * 1000)).issuedAt(new Date())
                .signWith(KEY, SignatureAlgorithm.HS256)
                .compact();
    }

    public String validateAndExtractUsername(String token) {
        return Jwts.parser()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

}
