package net.fadi.jwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.websocket.Decoder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    /*
       * the secret key to our algorithm to sign the token
       * get the key from website "https://www.allkeysgenerator.com/Random/Security-Encryption-Key-Generator.aspx"
       * the minimum size of key is 256 bit
       * get the key in Hex numeric system
     */
    private final String SECRET_KEY = "6D5A7134743777397A24432646294A404E635266556A586E3272357538782F41";
    public String extractUserEmail(String token) {
        // get Subject meains get user name or email (in our case email)
        return extractClaim(token, Claims::getSubject);
    }

    // method to get a specific claim from our token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    // this method to get the user info (in jwt called claims) from the token
    public Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // method to get the secret key after encrypt it (using HMAC algorithm)
    private Key getSignKey() {
        byte[] key = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    // method to generate token from the user info (here email and password)
    public String generateToken(UserDetails userDetails){
            return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * standard method to generate the toke
     * @Param extraClaims: contain an extra claims(info) if I want it inside the token
     * @Param userDetails: contain the info of user (username and password) but in our case we
                            are using email insted of username
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // this token is valid for a one day(I can change the value according the requirments)
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                // define the algorithm to encode the token (here HS256)
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // method to check if the token is valid (check if info the user is the same in token and token isn't expired)
    public boolean isTokenValid(String token, UserDetails userDetails){
        String email= extractUserEmail(token);
        return email.equals(userDetails.getUsername()) && !isExpiredToken(token);
    }

    // compare the expired date token from the current date
    private boolean isExpiredToken(String token) {
        return extractExpiration(token).before(new Date());
    }

    // extract the expired date from token
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
