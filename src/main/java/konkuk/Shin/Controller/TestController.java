package konkuk.Shin.Controller;

import konkuk.Shin.response.ApiResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

public class TestController {

    @GetMapping("/login")
     public ApiResponse<Void> getPromiseManagementPage(
            @RequestParam(value = "id", required = true) String id,
            @RequestParam(value = "password", required = true) String password
    ) {
        return ApiResponse.ok(null);
    }
}
