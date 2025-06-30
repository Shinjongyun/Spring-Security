package konkuk.Shin.Controller;

import konkuk.Shin.Oauth.Kakao.KakaoAuthService;
import konkuk.Shin.response.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class KakaoController {
    private final KakaoAuthService kakaoAuthService;

    @PostMapping("/login")
    public ApiResponse<Void> login() {
        kakaoAuthService.login();
        return ApiResponse.ok(null);
    }
}
