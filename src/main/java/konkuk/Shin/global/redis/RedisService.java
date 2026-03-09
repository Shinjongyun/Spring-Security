package konkuk.Shin.global.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, String> redisTemplate;

    public void setValues(String key, String data, Duration duration) {
        redisTemplate.opsForValue().set(key, data, duration);
    }

    /**
     * SETNX + EX 원자 처리
     * 키가 없을 때만 저장하고 true 반환, 이미 있으면 false 반환
     */
    public boolean setIfAbsent(String key, String data, Duration duration) {
        Boolean result = redisTemplate.opsForValue().setIfAbsent(key, data, duration);
        return Boolean.TRUE.equals(result);
    }

    public String getValues(String key) {
        String value = redisTemplate.opsForValue().get(key);
        return value != null ? value : "false";
    }

    public void delete(String key) {
        redisTemplate.delete(key);
    }

}
