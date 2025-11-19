package konkuk.Shin.auth.controller;

import com.umust.dobonglife.domain.auth.dto.request.RefreshTokenRequest;
import com.umust.dobonglife.domain.auth.dto.response.TokenResponse;
import com.umust.dobonglife.domain.auth.service.JwtService;
import com.umust.dobonglife.global.common.resolver.CurrentUserId;
import com.umust.dobonglife.global.common.response.BaseResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
@RequestMapping(("/api/auth"))
@RestController
public class AuthController {

    private final JwtService jwtService;

    @GetMapping("/login/kakao")
    public void redirectToKakao(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/kakao");
    }

    @GetMapping("/login/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }

    @PostMapping("/logout")
    public BaseResponse<Void> logout(HttpServletRequest request,
                                     @RequestBody RefreshTokenRequest tokenRequest){
        jwtService.logout(request, tokenRequest);
        return BaseResponse.ok(null);
    }

    @PostMapping("/reissue")
    public BaseResponse<TokenResponse> reissueTokens(@RequestBody RefreshTokenRequest tokenRequest,
                                                     @CurrentUserId Long userId) {
        TokenResponse response = jwtService.reissueTokens(tokenRequest, userId);
        return BaseResponse.ok(response);
    }
}
