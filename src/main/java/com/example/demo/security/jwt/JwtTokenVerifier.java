package com.example.demo.security.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Nonnull;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    @Nonnull HttpServletResponse httpServletResponse,
                                    @Nonnull FilterChain filterChain)
            throws ServletException, IOException {

        String authorizationHeader =
                httpServletRequest.getHeader("Authorization");

        if (Strings.isNullOrEmpty(authorizationHeader) ||
                !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        String token = authorizationHeader
                .replace("Bearer ", "");

        try {
            String key = "sfposnpsonişçögospngsonpngçöfşsfvcşzimv";

            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
                    .build()
                    .parseClaimsJws(token);

            Claims body = claimsJws.getBody();

            // type comes from the actual JWT body structure
            // list of singleton maps
            //noinspection unchecked
            var authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> grantedAuthorities =
                    authorities
                            .stream()
                            .map(authorityMap ->
                                    new SimpleGrantedAuthority(authorityMap.get("authority"))
                            )
                            .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    body.getSubject(),
                    null,
                    grantedAuthorities
            );

            SecurityContextHolder
                    .getContext()
                    .setAuthentication(authentication);
        } catch (JwtException e) {
            throw new IllegalStateException("Token cannot be validated:\n" + token);
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
