package com.example.demo.security.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;
import java.util.Optional;

public class JwtUserNamePasswordCredentialsAuthFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUserNamePasswordCredentialsAuthFilter(AuthenticationManager authenticationManager,
                                                    JwtConfig jwtConfig,
                                                    SecretKey secretKey) {
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response)
            throws AuthenticationException {

        UsernamePasswordAuthRequest authRequest =
                getAuthenticationRequest(request).orElseThrow();

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                authRequest.getUsername(),
                authRequest.getPassword()
        );

        return authenticationManager.authenticate(authentication);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {

        var twoWeeksFromNow =
                java.sql.Date.valueOf(
                        LocalDate.now()
                                .plusDays(
                                jwtConfig.getTokenExpirationAfterDays()
                                )
                );

        String token = Jwts.builder()
                .setSubject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(twoWeeksFromNow)
                .signWith(secretKey)
                .compact();

        response.addHeader(jwtConfig.getAuthorizationHeader(),
                jwtConfig.getTokenPrefix() + token);
    }

    private Optional<UsernamePasswordAuthRequest>
    getAuthenticationRequest(HttpServletRequest request) {

        Optional<UsernamePasswordAuthRequest> filter;

        try {
            filter = Optional.of(
                    new ObjectMapper()
                            .readValue(request.getInputStream(),
                                    UsernamePasswordAuthRequest.class)
            );
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return filter;
    }
}
