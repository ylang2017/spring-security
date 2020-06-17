package com.example.demo.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class MyAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * 自定义验证方式
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        System.out.println("触发自定义验证");
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        System.out.println("待验证信息：username:"+username+",pas:"+password);

        UserDetails user = userDetailsService.loadUserByUsername(username);
        if(user.getUsername() == null){
            System.out.println("无此用户，验证失败");
            return null;
        }
        System.out.println("模拟数据库信息：username:"+user.getUsername()+",pas:"+user.getPassword());

        //如果密码相同，则认为验证通过。
        if(user.getUsername().equals(username) && user.getPassword().equals(password)) {
            System.out.println("自定义验证成功");
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        }
        System.out.println("用户名或密码不正确");
        return null;
    }

    @Override
    public boolean supports(Class<?> arg0) {
        return true;
    }

}
