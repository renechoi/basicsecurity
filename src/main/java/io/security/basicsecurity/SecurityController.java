package io.security.basicsecurity;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

	@GetMapping("/")
	public String index(){
		return "home";
	}

	@GetMapping("loginPage")
	public String loginPage(){
		return "loginPage";
	}

	@GetMapping("/user")
		public String user(){
			return "user";
	}


	@GetMapping("/admin")
	public String admin(){
		return "admin";
	}

	@GetMapping("/login")
	public String login(){
		return "login";
	}

	@GetMapping("/denied")
	public String denied(){
		return "denied";
	}


	@GetMapping("/getcontext")
	public String index(HttpSession session){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		SecurityContext context = (SecurityContext)session.getAttribute(
			HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);

		Authentication authentication1 = context.getAuthentication();

		return null;
	}


}
