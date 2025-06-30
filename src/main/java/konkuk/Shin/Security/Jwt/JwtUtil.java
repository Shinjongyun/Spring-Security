package konkuk.Shin.Security.Jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
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
import java.util.Collection;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Getter
    @Value("${jwt.access.expiration}")
    private Long accessTokenExpirationPeriod;

    @Getter
    @Value("${jwt.refresh.expiration}")
    private Long refreshTokenExpirationPeriod;

    public static String getUsername(String token, Key signingKey) {
        return getClaims(token, signingKey).getSubject();
    }

    public static Date getExpiration(String token, Key signingKey) {
        return getClaims(token, signingKey).getExpiration();
    }

    public static boolean isTokenExpired(String token, Key signingKey) {
        return getExpiration(token, signingKey).before(new Date());
    }

    public static Claims getClaims(String token, Key signingKey) {
        return Jwts.parser()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public static boolean hasAdminRole() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        return authorities.stream().filter(o -> o.getAuthority().equals("ROLE_ADMIN")).findAny().isPresent();
    }
}
