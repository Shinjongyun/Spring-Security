package konkuk.Shin.auth.security.domain.constant;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Getter
public enum Role {

    MEMBER("MEMBER"),
    MANAGER("MANAGER"),
    ADMIN("ADMIN");

    Role(String value) {
        this.value = value;
        this.role = PREFIX + value;
    }

    public static final String PREFIX = "ROLE_";
    private final String value;
    private final String role;

    // 파싱된 값에 맞는 Role을 반환하는 메서드 (ROLE_MEMBER -> MEMBER)
    public static Role fromRole(String roleString) {
        if (roleString != null && roleString.startsWith(PREFIX)) {
            String roleValue = roleString.substring(PREFIX.length());
            for (Role role : Role.values()) {
                if (role.value.equalsIgnoreCase(roleValue)) {
                    return role;
                }
            }
        }
        throw new IllegalArgumentException("Unknown role: " + roleString);
    }

    // Role을 권한으로 변환하는 메서드 (MEMBER -> ROLE_MEMBER)
    public GrantedAuthority toAuthority() {
        return new SimpleGrantedAuthority(PREFIX + this.value);
    }
}
