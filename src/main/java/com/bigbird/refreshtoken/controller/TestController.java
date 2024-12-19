package com.bigbird.refreshtoken.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("${apiPrefix}/test")
public class TestController {
    @GetMapping
    public String hello() {
        return "Hello world!";
    }
}
