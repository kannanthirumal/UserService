package dev.kannan.userservice.services;

import dev.kannan.userservice.models.Token;
import dev.kannan.userservice.models.User;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserService{
    @Override
    public Token login(String email, String password) {
        return null;
    }

    @Override
    public User signup(String name, String email, String password) {
        return null;
    }

    @Override
    public User validateToken(String tokenValue) {
        return null;
    }

    @Override
    public void logout(String tokenValue) {

    }
}
