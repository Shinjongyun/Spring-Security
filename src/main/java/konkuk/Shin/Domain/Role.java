package konkuk.Shin.Domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("ROLE_USER"), ADMIN("ROLE_ADMIN");

    private final String key;

    public String toAuthority() {
        return "ROLE_" + this.name(); // 예: ROLE_USER
    }
}

