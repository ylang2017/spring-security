package com.example.demo.filter;

import com.example.demo.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

public class MyJWTLoginFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public MyJWTLoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) {
        System.out.println("触发登录拦截");
        //从登陆请求中提取用户填写的登陆信息
        User user = new ObjectMapper().readValue(req.getInputStream(), User.class);
        /*String username = req.getParameter("username");
        String password = req.getParameter("password");*/
        String username = user.getUsername();
        String password = user.getPassword();

        System.out.println("获取登录用户信息：" + username +",pas:"+password+ ",即将进行用户信息验证");

        //构建一个未验证的token
        Authentication token = new UsernamePasswordAuthenticationToken(username, password, new ArrayList<>());

        //使用authenticationManager调用相关handler去验证token
        return authenticationManager.authenticate(token);
    }

    /**
     * 重写验证成功后的回调
     * <p>
     * 登录成功后，把jwt信息组装提供给客户端
     *
     * @param req
     * @param res
     * @param chain
     * @param auth
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest req, HttpServletResponse res, FilterChain chain, Authentication auth) {
        System.out.println("登陆成功回调：");
        List<SimpleGrantedAuthority> roles = new ArrayList(auth.getAuthorities());
        roles.forEach((item)->System.out.println(item.getAuthority()));

        //json web token构建
        String token = Jwts.builder()
                //此处为自定义的、实现org.springframework.security.core.userdetails.UserDetails的类，需要和配置中设置的保持一致
                //此处的subject可以用一个用户名，也可以是多个信息的组合，根据需要来定
                .setSubject(((User) auth.getPrincipal()).getUsername())

                //设置权限
                .claim("ROLE",auth.getAuthorities())

                //设置token过期时间，3分钟
                .setExpiration(new Date(System.currentTimeMillis() + 3 * 60 * 1000))

                //设置token签名、密钥
                .signWith(SignatureAlgorithm.HS512, "MyJwtSecret")

                .compact();

        //返回token
        res.addHeader("Authorization", "Bearer " + token);
        res.setContentType("application/json;charset=utf-8");
        res.setStatus(HttpServletResponse.SC_OK);
    }

    /**
     * 重写验证失败后的回调
     *
     * @param request
     * @param response
     * @param failed
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        System.out.println("登录验证失败，提示未授权信息");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
