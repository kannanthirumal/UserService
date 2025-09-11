package dev.kannan.userservice.repositories;

import dev.kannan.userservice.models.Token;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Date;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {
    @Override
    Token save(Token token);

    Optional<Token> findByValue(String tokenValue);

    Optional<Token> findByValueAndIsDeletedAndExpiryGreaterThan(String tokenValue, boolean isDeleted, Long currentTime);
}
