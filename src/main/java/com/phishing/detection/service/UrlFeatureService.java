
package com.phishing.detection.service;

import java.net.URI;

import org.springframework.stereotype.Service;

import com.phishing.detection.dto.ScanResponse;

@Service
public class UrlFeatureService {

    public ScanResponse extractFeatures(String url) {

        URI uri = URI.create(url);

        int urlLength = url.length();
        int dotCount = countCharacter(url, '.');
        int hyphenCount = countCharacter(url, '-');
        int specialCharacterCount = countSpecialCharacters(url);
        int subdomainCount = countSubdomains(uri);

        boolean containsAtSymbol = url.contains("@");
        boolean usesIpAddress = isIpAddress(uri.getHost());
        boolean usesHttps =
                "https".equalsIgnoreCase(uri.getScheme());

        return new ScanResponse(
                "URL features extracted successfully",
                url,
                urlLength,
                dotCount,
                hyphenCount,
                specialCharacterCount,
                subdomainCount,
                containsAtSymbol,
                usesIpAddress,
                usesHttps
        );
    }

    private int countCharacter(String value, char character) {
        int count = 0;

        for (char current : value.toCharArray()) {
            if (current == character) {
                count++;
            }
        }

        return count;
    }

    private int countSpecialCharacters(String url) {
        int count = 0;

        for (char character : url.toCharArray()) {
            if (!Character.isLetterOrDigit(character)
                    && character != ':'
                    && character != '/'
                    && character != '.'
                    && character != '-') {
                count++;
            }
        }

        return count;
    }

    private int countSubdomains(URI uri) {
        String host = uri.getHost();

        if (host == null) {
            return 0;
        }

        String[] parts = host.split("\\.");

        return Math.max(0, parts.length - 2);
    }

    private boolean isIpAddress(String host) {
        if (host == null) {
            return false;
        }

        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }
}
