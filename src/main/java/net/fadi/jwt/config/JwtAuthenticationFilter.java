package net.fadi.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/*
    *this class doing the filter for each request from the user, so that extends
     it the "OncePerRequestFilter" class
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    // attribute to extract the user info form the jwt tokens
     private final JwtService jwtService;

     // attribute to check if user exist in the db
     private final UserDetailsService userDetailsService;

    //FilterChain: to call the next filter in Springboot when we finished from our jwt checking
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // check if the jwt exist in client request header
        String authHeader = request.getHeader("Authorization");
        String jwt ="";
        // if the jwt not exist, then I will continue to other Spring filter
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return;
        }

        //extract jwt from the Header (remove "Bearer " from the value)
        jwt = authHeader.substring(7);

        //extract user email from our jwt token
        String userEmail = jwtService.extractUserEmail(jwt);

        //if we have new user but isnt authenticated, then we have to check his info from db
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null){
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // here means the user is exist in db now I have to check if his token is valid
            if(jwtService.isTokenValid(jwt, userDetails)){

                // update "SecurityContextHolder" in spring to allow the user to access to project services
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // after doing our jwt filter, I tell spring to continue with own filter
        filterChain.doFilter(request, response);

    }
}
