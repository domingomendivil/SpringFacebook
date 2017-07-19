package com.example.demo;

import java.security.Principal;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class DemoApplication extends WebSecurityConfigurerAdapter {

	  @Autowired
	  OAuth2ClientContext oauth2ClientContext;
	
    @RequestMapping("/hello")
    @ResponseBody
    String home() {
        return "Hello World!";
    }
    
    @RequestMapping("/user")
    public Principal user(Principal principal) {
      return principal;
    }

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	
	  @Bean
	  @ConfigurationProperties("facebook.client")
	  public AuthorizationCodeResourceDetails facebook() {
	    return new AuthorizationCodeResourceDetails();
	  }
	  
	  @Bean
	  @ConfigurationProperties("facebook.resource")
	  public ResourceServerProperties facebookResource() {
	    return new ResourceServerProperties();
	  }

	private Filter ssoFilter() {
		  OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
		  OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
		  facebookFilter.setRestTemplate(facebookTemplate);
		  UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());
		  tokenServices.setRestTemplate(facebookTemplate);
		  facebookFilter.setTokenServices(tokenServices);
		  return facebookFilter;
		}
	
	public void run(String... arg0) throws Exception {
		// TODO Auto-generated method stub
		System.out.println("corriendo  ");
	}
	
	 @Override
	  protected void configure(HttpSecurity http) throws Exception {
	    http
	      .antMatcher("/**")
	      .authorizeRequests()
	        .antMatchers("/", "/login**", "/webjars/**")
	        .permitAll()
	      .anyRequest()
	        .authenticated().and().addFilterBefore(ssoFilter(),BasicAuthenticationFilter.class);
	  }
	 
	 
	 @Bean
	 public FilterRegistrationBean oauth2ClientFilterRegistration(
	     OAuth2ClientContextFilter filter) {
	   FilterRegistrationBean registration = new FilterRegistrationBean();
	   registration.setFilter(filter);
	   registration.setOrder(-100);
	   return registration;
	 }
}