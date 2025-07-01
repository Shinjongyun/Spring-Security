package konkuk.Shin.Security.Jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKeyPlain;

    private SecretKey signingKey;

    @Getter
    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Getter
    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    // secretKey 초기화 (Base64 디코딩 + HMAC-SHA256 키 생성)
    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(secretKeyPlain);
        this.signingKey = new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    // 공통 claims 파서
    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long getMemberId(String token) {
        return getClaims(token).get("memberId", Long.class);
    }

    public String getProviderId(String token) {
        return getClaims(token).get("providerId", String.class);
    }

    public String getRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    public String getTokenType(String token) {
        return getClaims(token).get("tokenType", String.class);
    }

    public Boolean isTokenExpired(String token) {
        return getClaims(token).getExpiration().before(new Date());
    }

    public static String getUsername(String token, Key key) {
        return getClaims(token, key).getSubject();
    }

    public static Date getExpiration(String token, Key key) {
        return getClaims(token, key).getExpiration();
    }

    public static boolean isTokenExpired(String token, Key key) {
        return getExpiration(token, key).before(new Date());
    }

    public static Claims getClaims(String token, Key key) {
        return Jwts.parser()
                .verifyWith((SecretKey) key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public static boolean hasAdminRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return authorities.stream()
                .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
    }
}
