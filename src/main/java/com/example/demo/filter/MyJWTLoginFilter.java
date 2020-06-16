package com.example.demo.filter;

import com.example.demo.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Date;

/**
 *
 * 自定义 MyJWTLoginFilter 继承自 AbstractAuthenticationProcessingFilter，并实现其中的三个默认方法。
 * attemptAuthentication方法中，我们从登录参数中提取出用户名密码，然后调用AuthenticationManager.authenticate()方法去进行自动校验。
 * 第二步如果校验成功，就会来到successfulAuthentication回调中，在successfulAuthentication方法中，
 * 将用户角色遍历然后用一个 , 连接起来，然后再利用Jwts去生成token，按照代码的顺序，生成过程一共配置了四个参数，
 * 分别是用户角色、主题、过期时间以及加密算法和密钥，然后将生成的token写出到客户端。
 *
 * 第二步如果校验失败就会来到unsuccessfulAuthentication方法中，在这个方法中返回一个错误提示给客户端即可。
 *
 */
public class MyJWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    /*protected MyJWTLoginFilter() {
        //拦截url为 "/login" 的POST请求
        super(new AntPathRequestMatcher("/login", "POST"));
    }*/
    public MyJWTLoginFilter(AuthenticationManager authenticationManager) {
        setAuthenticationManager(authenticationManager);
        super.setFilterProcessesUrl("/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)
            throws AuthenticationException{
        try{
            User user = new ObjectMapper().readValue(httpServletRequest.getInputStream(), User.class);
            return getAuthenticationManager().authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));
        }catch (IOException e){
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 重写验证成功后的回调
     *
     * 登录成功后，把jwt信息组装提供给客户端
     * @param request
     * @param response
     * @param chain
     * @param authResult
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        StringBuffer as = new StringBuffer();
        for (GrantedAuthority authority : authorities) {
            as.append(authority.getAuthority())
                    .append(",");
        }

        String jwt = Jwts.builder()
                .claim("authorities", as)//配置用户角色
                .setSubject(authResult.getName())
                .setExpiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(SignatureAlgorithm.HS512,"sang@123")
                .compact();
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write(new ObjectMapper().writeValueAsString(jwt));
        out.flush();
        out.close();
    }

    /**
     * 重写验证失败后的回调
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json;charset=utf-8");
        PrintWriter out = response.getWriter();
        out.write("登录失败!");
        out.flush();
        out.close();
    }
}
