package konkuk.Shin.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import konkuk.Shin.auth.controller.dto.response.TokenResponse;
import konkuk.Shin.auth.jwt.service.JwtStoreService;
import konkuk.Shin.auth.jwt.provider.JwtTokenProvider;
import konkuk.Shin.global.error.BusinessException;
import konkuk.Shin.global.error.ErrorCode;
import konkuk.Shin.user.service.UserService;
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

    private final JwtStoreService jwtStoreService;
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public void logout(HttpServletRequest request) {
        // 엑세스 토큰 추출 후 검증
        String accessToken = jwtTokenProvider.extractAccessToken(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.ACCESS_TOKEN_NOT_FOUND));
        jwtTokenProvider.validateAccessToken(accessToken);

        // 리프레쉬 토큰 추출 후 검증
        String refreshToken = jwtTokenProvider.extractRefreshToken(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.REFRESH_TOKEN_NOT_FOUND));
        jwtTokenProvider.validateRefreshToken(refreshToken);

        // 리프레쉬 토큰 삭제
        jwtStoreService.deleteRefreshToken(refreshToken);
        // 엑세스 토큰 블랙리스트화
        jwtStoreService.invalidAccessToken(accessToken);
    }

    @Transactional
    public TokenResponse reissueTokens(HttpServletRequest request, Long userId) {

        // 리프레쉬 토큰 추출 후 검증
        String refreshToken = jwtTokenProvider.extractRefreshToken(request)
                .orElseThrow(() -> new BusinessException(ErrorCode.REFRESH_TOKEN_NOT_FOUND));
        jwtTokenProvider.validateRefreshToken(refreshToken);

        // 새로운 Token 발급
        String reissuedAccessToken = jwtTokenProvider.createAccessToken(jwtTokenProvider.getUserId(refreshToken), jwtTokenProvider.getProvider(refreshToken), jwtTokenProvider.getRole(refreshToken), jwtTokenProvider.getName(refreshToken));
        String reissuedRefreshToken = jwtTokenProvider.createRefreshToken(jwtTokenProvider.getUserId(refreshToken), jwtTokenProvider.getProvider(refreshToken), jwtTokenProvider.getName(refreshToken));

        // 새로운 Refresh 저장
        jwtStoreService.storeRefreshToken(reissuedRefreshToken, userId);
        // 기존 Refresh Token 폐기
        jwtStoreService.deleteRefreshToken(refreshToken);

        return TokenResponse.builder()
                .accessToken(reissuedAccessToken)
                .refreshToken(reissuedRefreshToken)
                .build();
    }

    @Transactional
    public void deleteAccount(HttpServletRequest request, Long userId) {
    }
}
