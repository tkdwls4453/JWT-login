package com.example.jwtlogin.jwt;

import com.example.jwtlogin.domain.Member;
import com.example.jwtlogin.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@AllArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // 요청 헤더로부터 JWT 를 찾는다.
        String authorization = request.getHeader("Authorization");

        // authorization 검증
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            // 다음 필터로 그냥 넘김
            filterChain.doFilter(request, response);
            return;
        }

        // JWT 부분만 얻음
        String token = authorization.split(" ")[1];

        // JWT 가 유효한지 검사
        if (jwtUtil.isExpired(token)) {
            log.info("token expired");

            filterChain.doFilter(request, response);
            return;
        }

        // JWT 로 부터 username 과 role 을 획득
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        // password 에 제대로된 값이 굳이 필요없어 아무 문자열로 대체
        Member member = new Member(username, "password", role);

        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        // 스프링 시큐리티 인즌 토큰 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
