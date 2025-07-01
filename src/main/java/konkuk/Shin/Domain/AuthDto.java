package konkuk.Shin.Domain;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class AuthDto implements MemberPrincipal {

    private Long memberId;
    private String providerId;
    private String name;
    private String email;
    private Role role;

    @Builder
    public AuthDto(Long memberId, String providerId, String name, String email, Role role) {
        this.memberId = memberId;
        this.providerId = providerId;
        this.name = name;
        this.email = email;
        this.role = role;
    }

    public static AuthDto from(Member member, Auth auth) {
        return AuthDto.builder()
                .memberId(member.getId())
                .providerId(auth.getProviderId())
                .name(member.getNickname())
                .email(member.getEmail())
                .role(member.getRole())
                .build();
    }
}