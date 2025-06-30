package konkuk.Shin.Controller;

import konkuk.Shin.request.LoginRequestDTO;
import konkuk.Shin.response.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/login")
     public ApiResponse<Void> login(
            @RequestBody LoginRequestDTO request) {
        return ApiResponse.ok(null);
    }

    @GetMapping("/logout")
    public ApiResponse<Void> logout(
    ) {
        return ApiResponse.ok(null);
    }
}
