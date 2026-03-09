package konkuk.Shin.auth.service;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import konkuk.Shin.auth.controller.dto.response.TokenResponse;
import konkuk.Shin.auth.jwt.service.JwtService;
import konkuk.Shin.auth.jwt.provider.JwtTokenProvider;
import konkuk.Shin.auth.security.util.CookieUtil;
import konkuk.Shin.global.error.BusinessException;
import konkuk.Shin.global.error.ErrorCode;
import konkuk.Shin.user.service.UserService;
import org.springframework.beans.factory.annotation.Value;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * [AuthService]
 *
 * 인증 인가 도메인 관련
 * Jwt & User 서비스 계층 오케스트레이션 전담
 * **/
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Value("${jwt.refresh.expiration}")
    private Long REFRESH_TOKEN_EXPIRED_IN;

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response, Long userId) {
        // 엑세스 토큰 추출 후 검증
        String accessToken = jwtTokenProvider.extractAccessToken(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.ACCESS_TOKEN_NOT_FOUND));
        jwtTokenProvider.validateAccessToken(accessToken);

        // 엑세스 토큰 블랙리스트화
        jwtService.invalidAccessToken(accessToken);
        // 유저 키 삭제 (refresh 무효화)
        jwtService.deleteRefreshToken(userId);
        // 쿠키 삭제
        CookieUtil.deleteRefreshTokenCookie(response);
    }

    @Transactional
    public TokenResponse reissueTokens(HttpServletRequest request, HttpServletResponse response, Long userId) {

        // 리프레쉬 토큰 쿠키에서 추출 후 검증 + Claims 한 번만 파싱
        String refreshToken = CookieUtil.getRefreshTokenCookie(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.REFRESH_TOKEN_NOT_FOUND));
        Claims claims = jwtTokenProvider.validateRefreshToken(refreshToken);

        // Redis에 저장된 해시와 비교 (소유권 검증)
        Long tokenUserId = jwtTokenProvider.getUserId(claims);
        jwtService.validateRefreshTokenOwnership(refreshToken, tokenUserId);

        // Claims에서 값 추출 후 새로운 Token 발급
        String provider = jwtTokenProvider.getProvider(claims);
        String role = jwtTokenProvider.getRole(claims);
        String name = jwtTokenProvider.getName(claims);
        String reissuedAccessToken = jwtTokenProvider.createAccessToken(tokenUserId, provider, role, name);
        String reissuedRefreshToken = jwtTokenProvider.createRefreshToken(tokenUserId, provider, name);

        // 기존 삭제 → 새 Refresh 저장 (rotateRefreshToken은 덮어쓰기)
        jwtService.rotateRefreshToken(reissuedRefreshToken, userId);
        // 새 Refresh Token 쿠키에 저장
        CookieUtil.addRefreshTokenCookie(response, reissuedRefreshToken, REFRESH_TOKEN_EXPIRED_IN);

        return TokenResponse.builder()
                .accessToken(reissuedAccessToken)
                .build();
    }

    @Transactional
    public void deleteAccount(HttpServletRequest request, Long userId) {
    }
}
