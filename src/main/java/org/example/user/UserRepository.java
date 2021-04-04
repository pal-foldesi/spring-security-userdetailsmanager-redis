package org.example.user;

import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<RedisBackedUser, String> {
}