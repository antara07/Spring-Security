package com.example.spring.App;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class AppController {
	@Autowired
	MyUserDetailsService userDetailsService;
	@Autowired
	JwtUtil jwtUtil;
	@Autowired
	AuthenticationManager authManager;
	@RequestMapping("/get")
	public String getMessage(){
		return "Inside App";
	}
	@RequestMapping(value="/authenticate", method=RequestMethod.POST)
	public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest user) throws Exception{
		 try {
			// System.out.println("inside controller");
			authManager.authenticate(
					new UsernamePasswordAuthenticationToken(user.getUser(),user.getPassword()));
		 }
		 catch(BadCredentialsException ex){
			 throw new Exception("invalid username or password",ex);
		 }
		 
		final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUser());
		final String jwt= jwtUtil.generateToken(userDetails);
		 //System.out.print(jwt);
			return new ResponseEntity<>(jwt,HttpStatus.OK);
			
		}

}
