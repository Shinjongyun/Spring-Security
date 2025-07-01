package konkuk.Shin.Security.Filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.Domain.AuthDto;
import konkuk.Shin.Domain.CustomOAuth2User;
import konkuk.Shin.Security.Jwt.JwtProvider;
import konkuk.Shin.Security.Jwt.JwtUtil;
import konkuk.Shin.response.AuthException;
import konkuk.Shin.response.status.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;


// 토큰 추출
// 유효성 검사
// 사용자 인증 객체 생성
@Slf4j
@RequiredArgsConstructor
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;
    private final JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String accessToken = resolveToken(request);

        // 인증이 안 된 사용자가 보호된 URI 요청 → entryPoint 처리함
        if(accessToken == null) {
            log.info("JWT Filter Pass (accessToken is null) : {}", request.getRequestURI());
            SecurityContextHolder.getContext().setAuthentication(null);
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰 유효성 검사 (만기, 부적절한 토큰인 경우)
        try {
            jwtUtil.isTokenExpired(accessToken);
        } catch (ExpiredJwtException e) {
            throw new AuthException(ErrorCode.EXPIRED_ACCESS_TOKEN);
        } catch (Exception e) {
            throw new AuthException(ErrorCode.INVALID_ACCESS_TOKEN);
        }

        // 토큰 타입 검사
        if(!"access".equals(jwtUtil.getTokenType(accessToken))) {
            throw new AuthException(ErrorCode.INVALID_TOKEN_TYPE);
        }

        // 권한 리스트 생성
        List<GrantedAuthority> authorities = Arrays.asList(new SimpleGrantedAuthority(jwtUtil.getRole(accessToken)));
        log.info("Granted Authorities : {}", authorities);


        CustomOAuth2User customOAuth2User = new CustomOAuth2User(AuthDto.builder()
                .memberId(jwtUtil.getMemberId(accessToken))
                .providerId(jwtUtil.getProviderId(accessToken))
                .role(Role.fromRole(jwtUtil.getRole(accessToken)))
                .build(), authorities);

        log.info("CustomOAuth2User created: {}", customOAuth2User); // 생성된 사용자 정보 로깅
        log.info("CustomOAuth2User.providerId: {}", customOAuth2User.getProviderId());
        log.info("CustomOAuth2User.role: {}", customOAuth2User.getAuthorities().stream().findFirst().get().toString());
        log.info("CustomOAuth2User.memberId: {}", customOAuth2User.getMemberId());


        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        //세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);
        log.info("Authentication set in SecurityContext: {}", SecurityContextHolder.getContext().getAuthentication()); // SecurityContext 설정 확인 로깅
        log.info("Authorities in SecurityContext: {}", authToken.getAuthorities());

        log.info("JWT Filter Success : {}", request.getRequestURI());
        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION);
        log.info("token = {}", bearerToken);
        if((StringUtils.hasText(bearerToken)) && bearerToken.startsWith(jwtUtil.BEARER)) {
            log.info("token = {}", bearerToken);
            return bearerToken.substring(jwtUtil.BEARER.length());
        }
        return null;
    }
}
