package konkuk.Shin.user.repository;

import konkuk.Shin.user.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import konkuk.Shin.auth.security.domain.constant.Provider;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmailAndProvider(String email, Provider provider);
    Optional<User> findByProviderAndProviderId(Provider provider, String providerId);
    boolean existsByEmailAndProvider(String email, Provider provider);

    @Query(value = "SELECT * FROM users WHERE provider = :provider AND provider_id = :providerId AND status = 'INACTIVE' ORDER BY updated_at DESC LIMIT 1", nativeQuery = true)
    Optional<User> findInactiveByProviderAndProviderId(@Param("provider") String provider, @Param("providerId") String providerId);
}
