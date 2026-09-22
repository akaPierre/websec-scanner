package com.websec.scanner.scanner;

import com.websec.scanner.model.Finding;
import reactor.core.publisher.Mono;

import java.util.List;

public interface Scanner {

    Mono<List<Finding>> scan(String target);

    String getName();
}