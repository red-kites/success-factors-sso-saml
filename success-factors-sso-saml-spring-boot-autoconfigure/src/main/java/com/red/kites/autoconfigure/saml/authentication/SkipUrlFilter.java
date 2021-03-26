package com.red.kites.autoconfigure.saml.authentication;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class SkipUrlFilter extends OncePerRequestFilter {
    private static final MediaType TEXT_HTML_UTF8 = new MediaType(MediaType.TEXT_HTML, StandardCharsets.UTF_8);


    private final String spEntityID;

    private final String serverBaseUrl;


    public SkipUrlFilter(String spEntityID, String serverBaseUrl) {
        Assert.hasText(spEntityID, "请设置  security.oa.login.sp-entity-id");
        Assert.hasText(serverBaseUrl, "请设置  security.oa.login.server-base-url");
        this.spEntityID = spEntityID;
        this.serverBaseUrl = serverBaseUrl;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        response.setContentType(TEXT_HTML_UTF8.toString());
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || (authentication instanceof AnonymousAuthenticationToken)) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            PrintWriter printWriter = response.getWriter();
            printWriter.write("登录失败，请稍后重试");
            printWriter.flush();
        } else {
            StringBuilder builder = new StringBuilder();
            builder.append("<!DOCTYPE html>")
                    .append("<html lang=\"en\">")
                    .append("<head>")
                    .append("<meta charset=\"UTF-8\">");
            String skip = serverBaseUrl + "/saml/idp/init?sp=" + spEntityID;
            builder.append("<meta http-equiv=\"Refresh\" content=\"0.5;url=" + skip + "\"/>");
            builder.append("<title>DHR SSO</title>")
                    .append("</head>")
                    .append("<body></body>")
                    .append("</html>");
            response.getWriter().append(builder.toString());
        }
    }
}
