package com.mokaya.springsecurity.utils;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.CharArrayReader;
import java.security.Key;
import java.util.Date;
import java.util.logging.Logger;

@Component
public class JwtUtils {
    private static final Logger logger = Logger.getLogger(JwtUtils.class.getName());

    @Value( "${jwt.secret}")
    private String jwtSecret;

    @Value( "${jwt.expiration.ms}")
    private int jwtExpirationInMs;

    public String getJwtFromHeader(HttpServletRequest request) {
        String BearerToken = request.getHeader("Authorization");
        logger.info("BearerToken: " + BearerToken);
        if (BearerToken != null && BearerToken.startsWith("Bearer ")) {
            return BearerToken.substring(7);

        }
        return null;
    }

    public String generateToken(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .setSubject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationInMs))
                .signWith(key())
                .compact();
    }

    public String getUsernameFromJwt(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build().parseSignedClaims(token)
                .getPayload().getSubject();
    }

    public Key key() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    public boolean validateJwtToken(String authToken) {
        System.out.println("Validate");
       try {
           Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
           return true;

       } catch (MalformedJwtException e){
           logger.info("Invalid JWT token.");
       } catch (ExpiredJwtException e){
           logger.info("Expired JWT token.");
       } catch (UnsupportedJwtException e) {
           logger.info("Unsupported JWT token.");
       } catch (IllegalArgumentException e){
           logger.info("JWT claims string is empty.");
       }
       return false;
    }

}
