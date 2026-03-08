package konkuk.Shin.security.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Provider {
    LOCAL("local"),
    NAVER("naver"),
    KAKAO("kakao"),
    GOOGLE("google");

    private final String value;

    public static Provider fromProvider(String providerString) {
        if (providerString == null) throw new IllegalArgumentException("provider is null");
        for (Provider p : values()) {
            if (p.value.equalsIgnoreCase(providerString) || p.name().equalsIgnoreCase(providerString)) {
                return p;
            }
        }
        throw new IllegalArgumentException("Unknown provider: " + providerString);
    }
}
