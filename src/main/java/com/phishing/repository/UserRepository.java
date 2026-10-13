package com.phishing.detection.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.phishing.detection.entity.User;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);
}