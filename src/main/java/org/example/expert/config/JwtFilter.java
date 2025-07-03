package org.example.expert.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    // 필터링 필요없는 URI 배열
    private static final String[] FILTER_PASS_URI = {"/auth/signin", "/api/auth/signup"};

    private final JwtUtil jwtUtil;
    private final CustomUserDetailService customUserDetailService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String url = request.getRequestURI();
        if(!isFilterPassUri(url)){
            if (url.startsWith("/auth")) {
                filterChain.doFilter(request, response);
                return;
            }

            String bearerJwt = request.getHeader("Authorization");

            if (bearerJwt == null) {
                // 토큰이 없는 경우 400을 반환합니다.
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "JWT 토큰이 필요합니다.");
                return;
            }

            String jwt = jwtUtil.substringToken(bearerJwt);

            try {
                // JWT 유효성 검사와 claims 추출
                Claims claims = jwtUtil.extractClaims(jwt);
                if (claims == null) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "잘못된 JWT 토큰입니다.");
                    return;
                }

                UserRole userRole = UserRole.valueOf(claims.get("userRole", String.class));

            /*
            httpRequest.setAttribute("userId", Long.parseLong(claims.getSubject()));
            httpRequest.setAttribute("email", claims.get("email"));
            httpRequest.setAttribute("userRole", claims.get("userRole"));
             */

                String email = claims.get("email", String.class);

                if (url.startsWith("/admin")) {
                    // 관리자 권한이 없는 경우 403을 반환합니다.
                    if (!UserRole.ADMIN.equals(userRole)) {
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "관리자 권한이 없습니다.");
                        return;
                    }
                    filterChain.doFilter(request, response);
                    return;
                }

                CustomUserDetails customUserDetails = customUserDetailService.loadUserByUsername(email);
                // 인증 확인용으로
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        customUserDetails,
                        null,
                        customUserDetails.getAuthorities()
                );
                //인증 객체를 SecurityContextHolder에 등록
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);


                filterChain.doFilter(request, response);
            } catch (SecurityException | MalformedJwtException e) {
                log.error("Invalid JWT signature, 유효하지 않는 JWT 서명 입니다.", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "유효하지 않는 JWT 서명입니다.");
            } catch (ExpiredJwtException e) {
                log.error("Expired JWT token, 만료된 JWT token 입니다.", e);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "만료된 JWT 토큰입니다.");
            } catch (UnsupportedJwtException e) {
                log.error("Unsupported JWT token, 지원되지 않는 JWT 토큰 입니다.", e);
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "지원되지 않는 JWT 토큰입니다.");
            } catch (Exception e) {
                log.error("Internal server error", e);
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            }
        }

    }

    private boolean isFilterPassUri(String requestURI){
        // 필터링이 필요없는 uri일 경우 true 반환
        return PatternMatchUtils.simpleMatch(FILTER_PASS_URI, requestURI);
    }

}