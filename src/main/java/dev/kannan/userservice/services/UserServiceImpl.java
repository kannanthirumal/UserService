package dev.kannan.userservice.services;

import dev.kannan.userservice.exceptions.InvalidCredentialsException;
import dev.kannan.userservice.exceptions.InvalidTokenException;
import dev.kannan.userservice.exceptions.UserAlreadyExistsException;
import dev.kannan.userservice.models.Token;
import dev.kannan.userservice.models.User;
import dev.kannan.userservice.repositories.TokenRepository;
import dev.kannan.userservice.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.apache.commons.lang3.RandomStringUtils;


import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class UserServiceImpl implements UserService{
    /*
        BCryptPasswordEncoder is provided by Spring Security (spring-boot-starter-security).
        It is a password hashing utility that uses the BCrypt strong hashing function.
        I created a bean of BCryptPasswordEncoder in the configuration class.
        This encoder is used to hash (encode) passwords before storing them in the database,
        and to verify raw passwords against the stored hashed passwords during authentication.
    */

    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private UserRepository userRepository;
    private TokenRepository tokenRepository;

    /*
        Inject the value of the config property token.expiry.days here.
        If it’s not defined anywhere, use the default value 30."
    */
    @Value("${token.expiry.days:30}")
    private int tokenExpiryDays;

    public UserServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder, UserRepository userRepository, TokenRepository tokenRepository) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
    }

    @Override
    public Token login(String email, String password) {
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()){
            //throw an exception or redirect to signup
            //return null;
            throw new InvalidCredentialsException("Invalid email or password");
        }

        /* Match the password */
        User user = optionalUser.get();
        if (!bCryptPasswordEncoder.matches(password, user.getPassword())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        //login successful -> generate token
        Token token = new Token();
        /*
            using Apache-Commons-Lang3 library's "RandomStringUtils" class,
            I can generate random strings that can be used as unique IDs
            but it's not the only way
            I can also use UUID in java
            String uniqueId = UUID.randomUUID().toString();
            System.out.println(uniqueId);  // e.g., "f47ac10b-58cc-4372-a567-0e02b2c3d479"
         */

        token.setValue(RandomStringUtils.randomAlphanumeric(128));
        token.setUser(user);
        //setting expiry date which is 30 days from current date - it's a business decision
        //converted LocalDate to Date as the datatype of expiry is "Date" in the model
        //took help from stack overflow to get the below code

        LocalDate localDate = LocalDate.now().plusDays(tokenExpiryDays);
        Date expiryDate = Date.from(localDate.atStartOfDay(ZoneId.systemDefault()).toInstant());
        token.setExpiryAt(expiryDate);

        /*
            - if expiry was an epoch I would have added time in milliseconds for these 30days
            - added "expiryAt" date format and "expiry" epoch both
            - just for learning purpose
            - "L" - cast to long to prevent overflow
        */
        token.setExpiry(System.currentTimeMillis() + (30L * 24 * 60 * 60 * 1000)); //30 days in milliseconds


        return tokenRepository.save(token);
    }

    /*
        - UserAlreadyExistsException extends RuntimeException, which makes it unchecked.
        - So even though you wrote throws UserAlreadyExistsException, it's optional.
        - The interface method doesn't need to declare it, and no compile error will occur.
     */
    @Override
    public User signup(String name, String email, String password) {

        //check if user already exists
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isPresent()){
            throw new UserAlreadyExistsException("User with this email already exists!");
        }

        User user = new User();
        user.setName(name);
        user.setEmail(email);
        user.setPassword(bCryptPasswordEncoder.encode(password));

        return userRepository.save(user);
    }

    @Override
    public User validateToken(String tokenValue) {
        /* Instead of all this, I can write a custom JPA query in the repository */
        /*
             Optional<Token> optionalToken = tokenRepository.findByValue(tokenValue);
            if(optionalToken.isEmpty()){
                throw new InvalidTokenException("Invalid token");
            }

            Token token = optionalToken.get();
            if(token.getExpiry() < System.currentTimeMillis()){
                throw new InvalidTokenException("Token has expired");
            }

            if(token.isDeleted()) {
                throw new InvalidTokenException("Token has expired");
            }

            User user = token.getUser();
            if(user == null) {
                throw new RuntimeException("User not found for the token");
            }

            return user;
        */

        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeletedAndExpiryGreaterThan(
                tokenValue,
                false,
                System.currentTimeMillis()
        );

        if(optionalToken.isEmpty()){
            throw new InvalidTokenException("Invalid or expired token");
        }

        Token token = optionalToken.get();
        User user = token.getUser();
        return user;
    }

    @Override
    public void logout(String tokenValue) {
        Token token = tokenRepository.findByValue(tokenValue)
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired session."));

        //Optionally check expiry
        if (token.getExpiry() != null && token.getExpiry() < System.currentTimeMillis()) {
            throw new InvalidTokenException("Session has already expired.");
        }

        //Soft delete
        token.setDeleted(true);
        tokenRepository.save(token);
    }
}
