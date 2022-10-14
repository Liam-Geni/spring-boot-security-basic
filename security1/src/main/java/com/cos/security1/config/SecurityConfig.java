package com.cos.security1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration  //메모리에 올라와야함
@EnableWebSecurity //스프링 security 필터가 스프링 필터체인에 등록이됨
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)//secured 어노테이션 활성화, preAuthorize, PostAuthorization 어노테이션 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        // h2-console 사용에 대한 허용(CSRF, FrameOptions 무시)
        return (web) -> web.ignoring()
                .antMatchers("/h2-console/**");
    }
    //해당 메서드의 러턴되는 오브젝트를 Ioc로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd(){
        return new BCryptPasswordEncoder();
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //보안해체
        http.csrf().disable();
        //권한 부여
        http.authorizeRequests()
                //user로 시작하는 부분으로 들어오면 인증이 필요함
                .antMatchers("/user/**").authenticated()
                //manager으로 시작하는 부분에 들어오면 R0LE_ADMIN 이거나 ROLE_MANAGER이어야함
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
                //admin으로 시작하는 부분에 들어모녀 ROLE_ADMIN이어야함
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                //해당조건에 없는 곳은 모두 권한 허용
                .anyRequest().permitAll()
                .and()
                .formLogin()
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") //login 주소가 호출이되면 시큐리티가 낚아채서 대신 로그인을 진행해준다.
                .defaultSuccessUrl("/"); //
    }
}
