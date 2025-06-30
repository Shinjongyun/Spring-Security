package konkuk.Shin.Oauth.Kakao;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class KakaoOAuthClient {

    @Value("${kakao.auth.client-id}")
    private String CLIENT_ID;
    @Value("${kakao.auth.redirect-uri}")
    private String REDIRECT_URI;

    private final String AUTH_TOKEN_URL_HOST = "https://kauth.kakao.com";
    private final String USER_URL_HOST = "https://kapi.kakao.com";

    private final WebClient webClient = WebClient.builder()
            .baseUrl(AUTH_TOKEN_URL_HOST)
            .build();

    private final WebClient webUserClient = WebClient.builder()
            .baseUrl(USER_URL_HOST)
            .build();

    /**
     * 1. 액세스 토큰 요청
     */
    public Mono<Map> getAccessToken(String authorizationCode) {
        return webClient.post()
                .uri("/oauth/token")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .bodyValue("grant_type=authorization_code" +
                        "&client_id=" + CLIENT_ID +
                        "&redirect_uri=" + REDIRECT_URI +
                        "&code=" + authorizationCode)
                .retrieve()
                .bodyToMono(Map.class);
    }

    /**
     * 2. 사용자 정보 요청
     */
    public Mono<Map> getUserInfo(String accessToken) {
        return webClient.get()
                .uri("/v2/user/me")
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .retrieve()
                .bodyToMono(Map.class);
    }
}