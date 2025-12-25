package com.myproject.api;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.mail.MailSenderAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(excludeAutoConfiguration = MailSenderAutoConfiguration.class)
class ApiApplicationTests {

	@Test
	void contextLoads() {
		// Kiểm tra xem Application Context của Spring Boot có khởi tạo thành công không
	}

}