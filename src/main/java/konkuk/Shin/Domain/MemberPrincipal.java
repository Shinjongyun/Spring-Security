package konkuk.Shin.Domain;

public interface MemberPrincipal {
    String getEmail();
    Role getRole();
    String getProviderId();
    Long getMemberId();
    String getName();
}
