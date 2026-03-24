package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;

import java.util.List;

public interface Scanner {
    
    List<Finding> scan(String target);

    String getName();
}