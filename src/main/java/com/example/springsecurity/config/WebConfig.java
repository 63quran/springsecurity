package com.example.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 正常配置其他安全相关的内容
        //请求授权规则
        http.authorizeHttpRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");
        // 开启登录功能
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");


        //开启注销功能，跳到首页

        //防止网站攻击
        http.csrf().disable();//关闭csrf功能
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能  本质是cookie，默认保存两周，自定义接收前端的参数
        http.rememberMe().rememberMeParameter("remember");
    }

    //认证，springboot 2.1.x可以直接使用
    //密码编码：PasswordEncoder
    //在Spring Security  5.0+  新增了很多的加密方法


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        //一下设置正常应该读取数据库的内容
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("lwh").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("asdmin").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2");
    }
}
