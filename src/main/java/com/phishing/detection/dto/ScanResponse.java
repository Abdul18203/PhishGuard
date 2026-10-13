
package com.phishing.detection.dto;

public class ScanResponse {

    private String message;
    private String url;
    private int urlLength;
    private int dotCount;
    private int hyphenCount;
    private int specialCharacterCount;
    private int subdomainCount;
    private boolean containsAtSymbol;
    private boolean usesIpAddress;
    private boolean usesHttps;

    public ScanResponse() {
    }

    public ScanResponse(
            String message,
            String url,
            int urlLength,
            int dotCount,
            int hyphenCount,
            int specialCharacterCount,
            int subdomainCount,
            boolean containsAtSymbol,
            boolean usesIpAddress,
            boolean usesHttps) {

        this.message = message;
        this.url = url;
        this.urlLength = urlLength;
        this.dotCount = dotCount;
        this.hyphenCount = hyphenCount;
        this.specialCharacterCount = specialCharacterCount;
        this.subdomainCount = subdomainCount;
        this.containsAtSymbol = containsAtSymbol;
        this.usesIpAddress = usesIpAddress;
        this.usesHttps = usesHttps;
    }

    public String getMessage() { return message; }
    public String getUrl() { return url; }
    public int getUrlLength() { return urlLength; }
    public int getDotCount() { return dotCount; }
    public int getHyphenCount() { return hyphenCount; }
    public int getSpecialCharacterCount() { return specialCharacterCount; }
    public int getSubdomainCount() { return subdomainCount; }
    public boolean isContainsAtSymbol() { return containsAtSymbol; }
    public boolean isUsesIpAddress() { return usesIpAddress; }
    public boolean isUsesHttps() { return usesHttps; }
}
