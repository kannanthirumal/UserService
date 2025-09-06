package dev.kannan.userservice.services;

import dev.kannan.userservice.models.Token;
import dev.kannan.userservice.models.User;
import dev.kannan.userservice.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService{
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserRepository userRepository;

    public UserServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
    }

    @Override
    public Token login(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()){
            //throw an exception or redirect to signup
            return null;
        }

        /* Match the password */
        User user = optionalUser.get();
        if(bCryptPasswordEncoder.matches(password, user.getPassword())){
            //password mismatch
            return null;
        }

        //login successful -> generate token
        Token token = new Token();
        return token;
    }

    @Override
    public User signup(String name, String email, String password) {
        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));

        return userRepository.save(user);
    }

    @Override
    public User validateToken(String tokenValue) {
        return null;
    }

    @Override
    public void logout(String tokenValue) {

    }
}
