package konkuk.Shin.user.controller.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class SignupRequest {
    @NotNull(message = "이메일은 필수입니다")
    @Schema(description = "이메일", example = "dobonglife@gmail.com")
    private String email;
    @NotNull(message = "이름은 필수입니다")
    @Schema(description = "이름", example = "김도봉")
    private String name;
    @NotNull(message = "비밀번호는 필수입니다")
    @Schema(description = "비밀번호", example = "1234")
    private String password;
}
