package com.example.demo.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * 这个过滤器用于获取用户请求中携带的jwt信息
 * <p>
 * 首先从请求头中提取出 authorization 字段，这个字段对应的value就是用户的token。
 * 将提取出来的token字符串转换为一个Claims对象，再从Claims对象中提取出当前用户名和用户角色，
 * 创建一个UsernamePasswordAuthenticationToken放到当前的Context中，然后执行过滤链使请求继续执行下去。
 */
public class MyJWTCheckFilter extends BasicAuthenticationFilter {
    public MyJWTCheckFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * 在拦截器中获取token并解析，拿到用户信息，放置到SecurityContextHolder，这样便完成了spring security和jwt的整合。
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("用户请求："+request.getRequestURL());
        System.out.println("触发token验证，即将获取请求token,判断请求是否已授权。");
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        // 将Authentication写入SecurityContextHolder中供后续使用
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        System.out.println("已获取token,将token放入SecurityContextHolder中供后续使用");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String token = request.getHeader("Authorization");

        Claims claims = Jwts
                .parser()
                .setSigningKey("MyJwtSecret")
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody();
        String user = claims.getSubject();

        Collection<Map<String,String>> roles = claims.get("ROLE", Collection.class);
        List<SimpleGrantedAuthority> auths = new ArrayList<>();
        roles.forEach((authMap) -> auths.add(new SimpleGrantedAuthority(authMap.get("authority"))));

        if (user != null) {
            return new UsernamePasswordAuthenticationToken(user, null, auths);
        }
        return null;
    }
}
