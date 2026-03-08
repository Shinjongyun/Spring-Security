package konkuk.Shin.user.domain.entity;

import jakarta.persistence.*;
import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.constant.Role;
import konkuk.Shin.global.entity.BaseEntity;
import lombok.*;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
@Getter @Setter
@SQLDelete(sql = "UPDATE users SET status = 'INACTIVE' WHERE user_id = ?")
@SQLRestriction("status IN ('ACTIVE')")
public class User extends BaseEntity {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "user_id", nullable = false)
    private Long id;

    @Column
    private String email;

    @Column
    private String name;

    @Column(nullable = true)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    @Enumerated(EnumType.STRING)
    private Provider provider;

    @Column(name = "provider_id")
    private String providerId;
}
