package com.example.demo.security.auth;

import java.util.Optional;

public interface UserDao {
    Optional<User> getUserByUserName(String userName);
}
