
package com.phishing.detection.entity;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "scan_history")
public class ScanHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String url;

    private int urlLength;

    private int dotCount;

    private int hyphenCount;

    private int specialCharacterCount;

    private int subdomainCount;

    private boolean containsAtSymbol;

    private boolean usesIpAddress;

    private boolean usesHttps;

    private String prediction;

    private Double phishingScore;

    private Double legitimateScore;

    private String model;

    private LocalDateTime scannedAt;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = true)
    private User user;

    public ScanHistory() {
    }

    public Long getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getUrlLength() {
        return urlLength;
    }

    public void setUrlLength(int urlLength) {
        this.urlLength = urlLength;
    }

    public int getDotCount() {
        return dotCount;
    }

    public void setDotCount(int dotCount) {
        this.dotCount = dotCount;
    }

    public int getHyphenCount() {
        return hyphenCount;
    }

    public void setHyphenCount(int hyphenCount) {
        this.hyphenCount = hyphenCount;
    }

    public int getSpecialCharacterCount() {
        return specialCharacterCount;
    }

    public void setSpecialCharacterCount(int specialCharacterCount) {
        this.specialCharacterCount = specialCharacterCount;
    }

    public int getSubdomainCount() {
        return subdomainCount;
    }

    public void setSubdomainCount(int subdomainCount) {
        this.subdomainCount = subdomainCount;
    }

    public boolean isContainsAtSymbol() {
        return containsAtSymbol;
    }

    public void setContainsAtSymbol(boolean containsAtSymbol) {
        this.containsAtSymbol = containsAtSymbol;
    }

    public boolean isUsesIpAddress() {
        return usesIpAddress;
    }

    public void setUsesIpAddress(boolean usesIpAddress) {
        this.usesIpAddress = usesIpAddress;
    }

    public boolean isUsesHttps() {
        return usesHttps;
    }

    public void setUsesHttps(boolean usesHttps) {
        this.usesHttps = usesHttps;
    }

    public String getPrediction() {
        return prediction;
    }

    public void setPrediction(String prediction) {
        this.prediction = prediction;
    }

    public Double getPhishingScore() {
        return phishingScore;
    }

    public void setPhishingScore(Double phishingScore) {
        this.phishingScore = phishingScore;
    }

    public Double getLegitimateScore() {
        return legitimateScore;
    }

    public void setLegitimateScore(Double legitimateScore) {
        this.legitimateScore = legitimateScore;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public LocalDateTime getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(LocalDateTime scannedAt) {
        this.scannedAt = scannedAt;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
