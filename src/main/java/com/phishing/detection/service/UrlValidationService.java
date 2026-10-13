package com.phishing.detection.service;

import java.net.URI;

import org.springframework.stereotype.Service;

@Service
public class UrlValidationService {

    public boolean isValidUrl(String url) {

        if (url == null || url.isBlank()) {
            return false;
        }

        try {
            URI uri = URI.create(url);

            return ("http".equalsIgnoreCase(uri.getScheme())
                    || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null;

        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}