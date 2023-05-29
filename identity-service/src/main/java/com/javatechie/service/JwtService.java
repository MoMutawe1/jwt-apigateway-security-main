package com.javatechie.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {

    // Secret of 32 bit
    public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";


    public void validateToken(final String token) {
        Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token);
    }


    // this method will call the createToken in order to generate tokens.
    public String generateToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userName);
    }

    // claims is nothing but request header, payload and signature.
    private String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)  // this has info about the request header, payload and signature.
                .setSubject(userName)  // set username value as a token subject.
                .setIssuedAt(new Date(System.currentTimeMillis()))  // set time when request was created.
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // set expiration limit for the created token.
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact(); // type of algorithm used to encrypt your token.
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
