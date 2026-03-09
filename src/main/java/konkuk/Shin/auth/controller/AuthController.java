package konkuk.Shin.auth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import konkuk.Shin.auth.controller.dto.response.TokenResponse;
import konkuk.Shin.auth.service.AuthService;
import konkuk.Shin.global.resolver.CurrentUserId;
import konkuk.Shin.global.response.BaseResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Tag(name = "인증 & 인가 API", description = "인증 & 인가 관련 API")
@Slf4j
@RequiredArgsConstructor
@RequestMapping(("/api/auth"))
@RestController
public class AuthController {

    private final AuthService authService;

    @Operation(summary = "카카오 로그인", description = "카카오 로그인을 합니다.")
    @ApiResponse(
            responseCode = "200",
            description = "카카오 소셜 로그인에 성공하였습니다."
    )
    @GetMapping("/login/kakao")
    public void redirectToKakao(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/kakao");
    }

    @Operation(summary = "구글 로그인", description = "구글 로그인을 합니다.")
    @ApiResponse(
            responseCode = "200",
            description = "구글 소셜 로그인에 성공하였습니다."
    )
    @GetMapping("/login/google")
    public void redirectToGoogle(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }

    @Operation(summary = "로그아웃", description = "로그아웃을 합니다.")
    @ApiResponse(
            responseCode = "200",
            description = "로그아웃에 성공하였습니다."
    )
    @PostMapping("/logout")
    public BaseResponse<Void> logout(HttpServletRequest request,
                                     HttpServletResponse response,
                                     @CurrentUserId Long userId){
        authService.logout(request, response, userId);
        return BaseResponse.ok(null);
    }

    @Operation(summary = "토큰 재발급", description = "토큰을 재발급합니다." +
            " 리프레쉬 토큰은 쿠키에서 자동으로 전송됩니다.")
    @ApiResponse(
            responseCode = "200",
            description = "엑세스 토큰 재발급 성공하였습니다."
    )
    @PostMapping("/reissue")
    public BaseResponse<TokenResponse> reissueTokens(HttpServletRequest request,
                                                     HttpServletResponse response,
                                                     @CurrentUserId Long userId) {
        TokenResponse tokenResponse = authService.reissueTokens(request, response, userId);
        return BaseResponse.ok(tokenResponse);
    }
}
