package konkuk.Shin.auth.controller.dto.request;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LocalLoginRequest {
    private String email;
    private String password;
}
