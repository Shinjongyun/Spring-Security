package konkuk.Shin.auth.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Slf4j
@Controller
@RequestMapping("/api/login")
@RequiredArgsConstructor
public class TestLoginController {

    @GetMapping("/kakaoPage")
    public String kakaoLoginPage() {
        return "kakao-login"; // resources/templates/kakao-login.html
    }

    @GetMapping("/googlePage")
    public String googleLoginPage() {
        return "google-login";
    }

    @GetMapping("/successPage")
    public String successPage() {
        return "success"; // → templates/success.html
    }
}