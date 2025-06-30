package konkuk.Shin.Oauth.Kakao;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Transactional
public class KakaoAuthService {

    private final KakaoOAuthClient kakaoOAuthClient;

    public Mono<Map> login(String code) {
        return kakaoOAuthClient.getAccessToken(code)
                .flatMap(tokenMap -> {
                    String accessToken = (String) tokenMap.get("access_token");
                    return kakaoOAuthClient.getUserInfo(accessToken);
                });
    }
}
