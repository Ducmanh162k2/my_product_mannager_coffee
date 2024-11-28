package com.cnf.services;

import com.cnf.entity.PasswordResetToken;
import com.cnf.repository.IPasswordResetTokenRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PasswordResetTokenService {
    @Autowired
    private IPasswordResetTokenRepository verificationTokenRepository;

    public PasswordResetToken save(PasswordResetToken verificationToken) {
        verificationTokenRepository.save(verificationToken);
        return verificationToken;
    }

    public Optional<PasswordResetToken> findByUserId(Long userID) {
        return verificationTokenRepository.findByUserId(userID);
    }

    public Optional<PasswordResetToken> findByToken(String token) {
        return verificationTokenRepository.findByToken(token);
    }

    @Transactional
    public void delete(PasswordResetToken verificationToken) {
        verificationTokenRepository.delete(verificationToken);
    }

    public List<PasswordResetToken> findAll() {
        return verificationTokenRepository.findAll();
    }

    @Transactional
    public void deleteByToken(String token) {
        verificationTokenRepository.deleteByToken(token);
    }
}
