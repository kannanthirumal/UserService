package dev.kannan.userservice.repositories;

import dev.kannan.userservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Override
    Optional<User> findById(Long id);

    /*
        this save method acts like both create and update
        - if no id - it acts as create
        - if id is present - it acts as update
     */
    @Override
    User save(User user);

    Optional<User> findByEmail(String email);
}
