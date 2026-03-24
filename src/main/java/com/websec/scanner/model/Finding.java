package com.websec.scanner.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Finding {
    
    private FindingType type;
    private Severity severity;
    private String title;
    private String description;
    private String evidence;
    private String recommendation;
    private String target;          // ex: "http://sub.example.com"
}