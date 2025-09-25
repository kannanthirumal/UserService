package dev.kannan.userservice.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import dev.kannan.userservice.models.Token;
import dev.kannan.userservice.models.User;

public interface UserService {
    Token login(String email, String password);
    User signup(String name, String email, String password);
    User validateToken(String tokenValue);
    void logout(String tokenValue);
}
