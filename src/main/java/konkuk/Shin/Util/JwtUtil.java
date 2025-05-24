package konkuk.Shin.Util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

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

    private static final String ACCESS_TOKEN_SUBJECT = "AccessToken";
    private static final String REFRESH_TOKEN_SUBJECT = "RefreshToken";
    private static final String USER_INFO_CLAIM = "userInfo";

    public String createAccessToken(String email) {
        String jwt = Jwts.builder()                     // (1)

                .header()                                   // (2) optional
                .keyId("aKeyId")
                .and()

                .subject("Bob")                             // (3) JSON Claims, or
                //.content(aByteArray, "text/plain")        //     any byte[] content, with media type

                .signWith(getSigningKey())                       // (4) if signing, or
                //.encryptWith(key, keyAlg, encryptionAlg)  //     if encrypting

                .compact();                                 // (5)
        return jwt;
    }

    public Jws<Claims> extractUserInfo(String token) {
        Jws<Claims> jwt;

        try {
            jwt = Jwts.parser()
                    // JWS일때는 같은 키를 사용해야 한다.
                    .verifyWith(getSigningKey())
                    // parser를 빌드한다.
                    .build()
                    // 서명된 클레임(token)을 파싱한다.
                    .parseSignedClaims(token);

            // 페이로드를 가져온다.
            Object payload = jwt.getPayload();
            // 페이로드를 출력한다. 출력 => "payload = {userId=1}"
            System.out.println("payload = " + payload);

        // JwtException 예외를 캐치한다. (읽기에 실패한다면!, 유효하지 않다면!)
        } catch (JwtException e) {
            throw new IllegalStateException("Invalid Token. " + e.getMessage());
        }
        return jwt;
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(keyBytes, "HmacSHA256"); // 알고리즘은 HS256이면 HmacSHA256
    }
}
