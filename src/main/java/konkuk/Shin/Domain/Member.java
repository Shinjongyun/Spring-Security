package konkuk.Shin.Domain;

import jakarta.persistence.*;
import konkuk.Shin.Common.BaseEntity;
import konkuk.Shin.Common.enums.Status;
import lombok.*;

import java.time.LocalDate;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter
public class Member extends BaseEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", nullable = false)
    private Long id;

    @Column
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Column(columnDefinition = "TEXT")
    private String memberProfileImageUrl;

    @Column(columnDefinition = "DATE")
    private LocalDate birthday;

    private String skinType;
    private String scalpType;
    private String hairType;
    private String personalColor;
    @Column(columnDefinition = "TINYINT(1)")
    private Boolean displayInProfile;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;

    @OneToOne(mappedBy = "member")
    private Auth auth;

    public static Member of(String email, Role role) {
        return Member.builder()
                .email(email)
                .role(role)
                .status(Status.ACTIVE)
                .build();
    }
}
