package com.example.demo.service;

import com.example.demo.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Component
public class MyUserDetailsService implements UserDetailsService {

    /**
     * 登陆验证时，通过username获取用户的所有权限信息
     * 并返回UserDetails放到spring的全局缓存SecurityContextHolder中，以供授权器使用
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<GrantedAuthority> adminAuth = new ArrayList<>();
        adminAuth.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        adminAuth.add(new SimpleGrantedAuthority("ROLE_USER"));

        List<GrantedAuthority> userAuth = new ArrayList<>();
        userAuth.add(new SimpleGrantedAuthority("ROLE_USER"));

        //在这里可以自己调用数据库，对username进行查询，看看在数据库中是否存在
        if("tom".equals(username)){
            System.out.println("模拟读取数据库用户信息，返回读取对象：tom,内置密码：123456");
            User myUserDetail = new User();
            myUserDetail.setUsername("tom");
            myUserDetail.setPassword("123456");
            myUserDetail.setAuthorities(userAuth);
            return myUserDetail;
        }else if("admin".equals(username)){
            System.out.println("模拟读取数据库用户信息，返回读取对象：admin,内置密码：admin");
            User myUserDetail = new User();
            myUserDetail.setUsername("admin");
            myUserDetail.setPassword("admin");
            myUserDetail.setAuthorities(adminAuth);
            return myUserDetail;
        }
        return new User();
    }
}
