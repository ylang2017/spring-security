package com.example.demo.config;

import com.example.demo.filter.MyJWTCheckFilter;
import com.example.demo.filter.MyJWTLoginFilter;
import com.example.demo.provider.MyAuthenticationProvider;
import com.example.demo.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private MyAuthenticationProvider provider;

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private MyPasswordEncoder myPasswordEncoder;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            //关闭跨站请求防护
            .cors().and().csrf().disable()

            //登陆设置
            .formLogin()//参数必须以表单的方式传递
                .loginPage("/login.html")//用户未登录时，访问任何资源都转跳到该路径，即登录页面
                .loginProcessingUrl("/loginAction")//登录表单form中action的地址，也就是处理认证请求的路径
                //.usernameParameter("username")///登录表单form中用户名输入框input的name名，不修改的话默认是username
                //.passwordParameter("password")//form中密码输入框input的name名，不修改的话默认是password
                .defaultSuccessUrl("/index.html")//登录认证成功后默认转跳的路径

            .and()
            //访问权限
            .authorizeRequests()
            //不需要通过登录验证就可以被访问的资源路径
            .antMatchers("/test","/login.html","/index.html","/loginAction").permitAll()
            //需要角色权限访问
            .antMatchers("/admin").hasAnyAuthority("ROLE_ADMIN")  //前面是资源的访问路径、后面是资源的名称或者叫资源ID
            .antMatchers("/user").hasAnyAuthority("ROLE_USER")  //前面是资源的访问路径、后面是资源的名称或者叫资源ID
            //其他的需要授权后访问
            .anyRequest().authenticated()

            .and()
            //增加登陆验证
            .addFilter(new MyJWTLoginFilter(authenticationManager()))
            //增加登陆过滤
            .addFilter(new MyJWTCheckFilter(authenticationManager()))
            //前后端分离是无状态的，所以不用session，將登陆信息保存在token中。
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        //覆盖UserDetailsService类,自定义用户信息来源,自定义密码加密方式
        auth.userDetailsService(myUserDetailsService).passwordEncoder(myPasswordEncoder);
        //自定义用户信息验证规则
        auth.authenticationProvider(provider);
    }
}
