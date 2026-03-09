package konkuk.Shin.auth.jwt.service;

import konkuk.Shin.auth.security.exception.CustomAuthenticationException;
import konkuk.Shin.global.redis.RedisService;
import konkuk.Shin.global.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

/**
 * [JwtService]
 * JWT Redis 저장 및 중복 로그인 방지 담당
 *
 * Redis 키 구조:
 *   auth:user:{userId}  → SHA-256(refreshToken)   (SETNX + TTL)
 *   auth:blacklist:{accessTokenHash} → "logout"    (TTL = access 만료시간)
 **/
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.access.expiration}")
    private Long ACCESS_TOKEN_EXPIRED_IN;

    @Value("${jwt.refresh.expiration}")
    private Long REFRESH_TOKEN_EXPIRED_IN;

    private static final String USER_KEY_PREFIX = "auth:user:";
    private static final String BLACKLIST_KEY_PREFIX = "auth:blacklist:";
    private static final String LOGOUT_VALUE = "logout";

    private final RedisService redisService;

    /**
     * Refresh Token 저장 (SETNX + EX 원자 처리)
     * 이미 로그인된 유저면 저장 실패 → 중복 로그인 차단
     */
    public void storeRefreshToken(String refreshToken, Long userId) {
        String key = USER_KEY_PREFIX + userId;
        String tokenHash = hashToken(refreshToken);

        boolean stored = redisService.setIfAbsent(key, tokenHash, Duration.ofMillis(REFRESH_TOKEN_EXPIRED_IN));
        if (!stored) {
            throw new CustomAuthenticationException(ErrorCode.DUPLICATED_LOGIN);
        }
    }

    /**
     * Refresh Token 검증 (쿠키의 토큰 해시 vs Redis 저장 해시 비교)
     */
    public void validateRefreshTokenOwnership(String refreshToken, Long userId) {
        String key = USER_KEY_PREFIX + userId;
        String storedHash = redisService.getValues(key);
        String requestHash = hashToken(refreshToken);

        if (!requestHash.equals(storedHash)) {
            throw new CustomAuthenticationException(ErrorCode.SECURITY_UNAUTHORIZED);
        }
    }

    /**
     * Refresh Token 삭제 (로그아웃 시)
     */
    public void deleteRefreshToken(Long userId) {
        redisService.delete(USER_KEY_PREFIX + userId);
    }

    /**
     * Refresh Token 갱신 (재발급 시: 기존 삭제 → 새로 저장)
     */
    public void rotateRefreshToken(String newRefreshToken, Long userId) {
        String key = USER_KEY_PREFIX + userId;
        String tokenHash = hashToken(newRefreshToken);
        redisService.setValues(key, tokenHash, Duration.ofMillis(REFRESH_TOKEN_EXPIRED_IN));
    }

    /**
     * Access Token 블랙리스트 등록 (로그아웃 시)
     */
    public void invalidAccessToken(String accessToken) {
        String key = BLACKLIST_KEY_PREFIX + hashToken(accessToken);
        redisService.setValues(key, LOGOUT_VALUE, Duration.ofMillis(ACCESS_TOKEN_EXPIRED_IN));
    }

    /**
     * Access Token 블랙리스트 확인
     */
    public void checkBlacklistedToken(String accessToken) {
        String key = BLACKLIST_KEY_PREFIX + hashToken(accessToken);
        String value = redisService.getValues(key);
        if (LOGOUT_VALUE.equals(value)) {
            throw new CustomAuthenticationException(ErrorCode.SECURITY_UNAUTHORIZED);
        }
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 알고리즘을 찾을 수 없습니다.", e);
        }
    }
}
