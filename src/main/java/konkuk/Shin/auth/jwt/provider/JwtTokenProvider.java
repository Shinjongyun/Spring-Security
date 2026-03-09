package konkuk.Shin.auth.jwt.provider;

import konkuk.Shin.auth.jwt.exception.CustomJwtException;
import konkuk.Shin.global.error.ErrorCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;


/**
 * [JwtTokenProvider]
 * JWT 기술 처리 전담
 * 토큰을 어떻게 만들고 해석하는지 담당
 * **/
@Slf4j
@Component
public class JwtTokenProvider {

    private final SecretKey secretKey;

    @Value("${jwt.access.expiration}")
    private Long ACCESS_TOKEN_EXPIRED_IN;

    @Value("${jwt.refresh.expiration}")
    private Long REFRESH_TOKEN_EXPIRED_IN;

    @Value("${jwt.access.header}")
    private String ACCESS_HEADER;

    @Value("${jwt.refresh.header}")
    private String REFRESH_HEADER;

    public final String BEARER_PREFIX = "Bearer ";

    public JwtTokenProvider(@Value("${jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 토큰을 한 번만 파싱하여 Claims 객체를 반환
     * 이후 getter 메서드들은 이 Claims를 재사용
     */
    public Claims getClaims(String token) {
        return Jwts.parser().verifyWith(secretKey).build()
                .parseSignedClaims(token).getPayload();
    }

    public Long getUserId(Claims claims) {
        return claims.get("userId", Long.class);
    }

    public String getProvider(Claims claims) {
        return claims.get("provider", String.class);
    }

    public String getRole(Claims claims) {
        return claims.get("role", String.class);
    }

    public String getTokenType(Claims claims) {
        return claims.get("tokenType", String.class);
    }

    public String getEmail(Claims claims) {
        return claims.get("email", String.class);
    }

    public String getName(Claims claims) {
        return claims.get("name", String.class);
    }

    public String createAccessToken(Long userId, String provider, String role, String name) {

        return Jwts.builder()
                .claim("tokenType", "access")
                .claim("userId", userId)
                .claim("provider", provider)
                .claim("name", name)
                .claim("role", role)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRED_IN))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    public String createRefreshToken(Long userId, String provider, String name) {

        return Jwts.builder()
                .claim("tokenType", "refresh")
                .claim("userId", userId)
                .claim("provider", provider)
                .claim("name", name)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRED_IN))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Access 토큰 검증 후 Claims 반환 (파싱 1회로 통합)
     */
    public Claims validateAccessToken(String accessToken) {
        Claims claims = validateToken(accessToken);

        if (!"access".equals(getTokenType(claims))) {
            throw new CustomJwtException(ErrorCode.INVALID_ACCESS_TOKEN_TYPE);
        }
        return claims;
    }

    /**
     * Refresh 토큰 검증 후 Claims 반환 (파싱 1회로 통합)
     */
    public Claims validateRefreshToken(String refreshToken) {
        Claims claims = validateToken(refreshToken);

        if (!"refresh".equals(getTokenType(claims))) {
            throw new CustomJwtException(ErrorCode.INVALID_REFRESH_TOKEN_TYPE);
        }
        return claims;
    }

    private Claims validateToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) { // 토큰 만료
            throw new CustomJwtException(ErrorCode.EXPIRED_ACCESS_TOKEN);
        } catch (UnsupportedJwtException e) { // 지원되지 않는 형식
            throw new CustomJwtException(ErrorCode.UNSUPPORTED_TOKEN_TYPE);
        } catch (MalformedJwtException e) { // 구조가 잘못된 토큰
            throw new CustomJwtException(ErrorCode.MALFORMED_TOKEN_TYPE);
        } catch (SignatureException e) { // 서명 위조 (곧 지원 중단)
            throw new CustomJwtException(ErrorCode.INVALID_SIGNATURE_JWT);
        } catch (IllegalArgumentException e) { // 토큰이 비어 있거나 Null
            throw new CustomJwtException(ErrorCode.EMPTY_AUTHORIZATION_HEADER);
        } catch (Exception e) { // 기타 예외 상황
            throw new CustomJwtException(ErrorCode.SECURITY_INVALID_TOKEN);
        }
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(ACCESS_HEADER))
                .filter(accessToken -> accessToken.startsWith(BEARER_PREFIX))
                .map(accessToken -> accessToken.replace(BEARER_PREFIX, ""));
    }

    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(REFRESH_HEADER))
                .filter(refreshToken -> refreshToken.startsWith(BEARER_PREFIX))
                .map(refreshToken -> refreshToken.replace(BEARER_PREFIX, ""));
    }
}
