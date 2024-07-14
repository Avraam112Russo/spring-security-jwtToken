package com.n1nt3nd0.springsecurityexample.security;

import com.n1nt3nd0.springsecurityexample.model.UserEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret_key;
    private final long accessTokenValidity = 60*60*1000;
    private final String TOKEN_HEADER = "Authorization";
    private final String TOKEN_PREFIX = "Bearer ";
    private SecretKey getSignInKey() { // secret key for sign
        byte[] keyBytes = Decoders.BASE64.decode(this.secret_key);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    public String createToken(UserEntity user) {
        Map<String, Object> claims = new HashMap<>(){{
            put("email", user.getEmail()); // claims body
        }};
        Date createdAt = new Date();
        Date expirationDate = new Date(createdAt.getTime() + TimeUnit.MINUTES.toMillis(accessTokenValidity));
        return Jwts.builder()
                .claims(claims)
                .issuer("avraam112russo") // avraam112russo
                .subject(user.getFirstName()) // userID
                .issuedAt(createdAt)
                .id(UUID.randomUUID().toString())
                .expiration(expirationDate)
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }
    private Claims parseJwtClaims(String token) {
        return getClaimsFromToken(token);
    }

    public Claims resolveClaims(HttpServletRequest req) {
        try {
            String token = resolveToken(req);
            if (token != null) {
                return parseJwtClaims(token);
            }
            return null;
        } catch (ExpiredJwtException ex) {
            req.setAttribute("expired", ex.getMessage());
            throw ex;
        } catch (Exception ex) {
            req.setAttribute("invalid", ex.getMessage());
            throw ex;
        }
    }
    public String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader(TOKEN_HEADER);
        if (bearerToken != null && bearerToken.startsWith(TOKEN_PREFIX)) {
            return bearerToken.substring(TOKEN_PREFIX.length());
        }
        return null;
    }

    public boolean validateClaims(Claims claims) throws AuthenticationException {
        try {
            return claims.getExpiration().after(new Date());
        } catch (Exception e) {
            throw e;
        }
    }

    public Claims getClaimsFromToken(String token){
        byte[] keyBytes = Decoders.BASE64.decode(secret_key);
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getBody();
    }
    public String getEmailFromClaims(Claims claims){
        String email = claims.get("email", String.class);
        return email;
    }

//    private List<String> getRoles(Claims claims) {
//        return (List<String>) claims.get("roles");
//    }
}
