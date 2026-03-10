package com.example.signature.dto;

public record DigestComparisonResponse(
        String providedFileName,
        String referenceUri,
        String expectedDigest,
        String calculatedDigest,
        boolean matches,
        String transformedXml
) {
}
