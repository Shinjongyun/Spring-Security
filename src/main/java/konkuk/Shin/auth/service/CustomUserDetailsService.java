package konkuk.Shin.auth.service;


import com.umust.dobonglife.domain.auth.model.Provider;
import com.umust.dobonglife.domain.auth.model.UserPrincipal;
import com.umust.dobonglife.domain.user.model.User;
import com.umust.dobonglife.domain.user.repository.UserRepository;
import com.umust.dobonglife.global.common.response.ErrorCode;
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
