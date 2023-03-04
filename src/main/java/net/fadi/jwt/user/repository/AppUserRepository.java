package net.fadi.jwt.user.repository;

import net.fadi.jwt.user.entity.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Integer> {

    public Optional<AppUser> findByEmail(String email);
}
