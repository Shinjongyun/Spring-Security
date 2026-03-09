package konkuk.Shin.auth.jwt.service;

import konkuk.Shin.auth.security.exception.CustomAuthenticationException;
import konkuk.Shin.global.redis.RedisService;
import konkuk.Shin.global.error.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * [JwtService]
 * JWT Redis에 저장 및 삭제 로직 담당
 * **/
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.access.expiration}")
    private Long ACCESS_TOKEN_EXPIRED_IN;

    @Value("${jwt.refresh.expiration}")
    private Long REFRESH_TOKEN_EXPIRED_IN;

    private static final String LOGOUT_VALUE = "logout";
    private static final String REFRESH_TOKEN_KEY_PREFIX = "auth:refresh:";

    private final RedisService redisService;

    public void checkBlacklistedToken(String accessToken) {
        String value = redisService.getValues(accessToken);
        if (value.equals(LOGOUT_VALUE)) {
            throw new CustomAuthenticationException(ErrorCode.SECURITY_UNAUTHORIZED);
        }
    }

    public void storeRefreshToken(String refreshToken, Long userId) {
        redisService.setValues(REFRESH_TOKEN_KEY_PREFIX+refreshToken, String.valueOf(userId), Duration.ofMillis(REFRESH_TOKEN_EXPIRED_IN));
    }

    public void deleteRefreshToken(String refreshToken){
        redisService.delete(REFRESH_TOKEN_KEY_PREFIX+refreshToken);
    }

    public void invalidAccessToken(String accessToken) {
        redisService.setValues(accessToken, LOGOUT_VALUE,
                Duration.ofMillis(ACCESS_TOKEN_EXPIRED_IN));
    }
}
