package konkuk.Shin.auth.security.local;

import konkuk.Shin.auth.security.domain.constant.Provider;
import konkuk.Shin.auth.security.domain.entity.UserPrincipal;
import konkuk.Shin.global.error.ErrorCode;
import konkuk.Shin.user.domain.entity.User;
import konkuk.Shin.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserPrincipal loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmailAndProvider(email, Provider.LOCAL)
                .orElseThrow(() -> new UsernameNotFoundException(ErrorCode.USER_NOT_FOUND.getMessage()));

        return UserPrincipal.builder()
                .userId(user.getId())
                .userName(user.getEmail())
                .password(user.getPassword())
                .provider(user.getProvider())
                .authorities(Collections.singleton(user.getRole().toAuthority()))
                .build();
    }
}
