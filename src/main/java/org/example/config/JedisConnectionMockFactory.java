package org.example.config;

import com.fiftyonred.mock_jedis.MockJedis;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnection;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import redis.clients.jedis.Jedis;

public class JedisConnectionMockFactory extends JedisConnectionFactory {
    private static final Jedis jedis = new MockJedis("localhost");

    @Override
    public RedisConnection getConnection() {
        JedisConnection connection = new JedisConnection(jedis);
        return postProcessConnection(connection);
    }
}
