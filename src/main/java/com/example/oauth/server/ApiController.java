package com.example.oauth.server;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api")
public class ApiController {

    @GetMapping("invoke")
    public String invoke() {
        return "success";
    }

}
