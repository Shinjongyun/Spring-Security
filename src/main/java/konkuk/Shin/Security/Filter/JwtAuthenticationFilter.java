package konkuk.Shin.Security.Filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.Security.Jwt.JwtProvider;
import konkuk.Shin.Security.Jwt.JwtUtil;
import konkuk.Shin.response.AuthException;
import konkuk.Shin.response.status.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = jwtProvider.resolveToken(request);

        if (token != null) {
            // 유효성 검증에 실패하면 JwtException, ExpiredJwtException 등을 던지도록 한다.
            if (!jwtProvider.validateToken(token)) {
                throw new AuthException(ErrorCode.SECURITY_INVALID_TOKEN); // 커스텀 AuthException
            }
            Authentication authentication = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
    }
}
