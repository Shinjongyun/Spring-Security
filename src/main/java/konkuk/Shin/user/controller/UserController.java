package konkuk.Shin.user.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import konkuk.Shin.auth.service.AuthService;
import konkuk.Shin.global.resolver.CurrentUserId;
import konkuk.Shin.global.response.BaseResponse;
import konkuk.Shin.user.controller.dto.request.SignupRequest;
import konkuk.Shin.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Tag(name = "사용자 API", description = "사용자 관련 API")
@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;
    private final AuthService authService;

    @Operation(summary = "회원 가입", description = "회원 가입을 합니다." +
            " role은 MEMBER, MANAGER, ADMIN 3개 입니다.")
    @ApiResponse(
            responseCode = "200",
            description = "회원가입에 성공하였습니다."
    )
    @PostMapping("/signup")
    public BaseResponse<Void> signUp(@Valid @RequestBody SignupRequest request) {
        userService.signUp(request);
        return BaseResponse.ok(null);
    }

    @Operation(summary = "회원 탈퇴", description = "회원 탈퇴를 합니다.")
    @ApiResponse(
            responseCode = "200",
            description = "회원탈퇴에 성공하였습니다."
    )
    @PostMapping("/delete/account")
    public BaseResponse<Void> deleteAccount(HttpServletRequest request,
                                            @CurrentUserId Long userId){
        authService.deleteAccount(request, userId);
        return BaseResponse.ok(null);
    }
}

