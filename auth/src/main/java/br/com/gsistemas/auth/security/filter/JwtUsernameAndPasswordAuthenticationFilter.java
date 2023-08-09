package br.com.gsistemas.auth.security.filter;

import br.com.gsistemas.core.model.ApplicationUser;
import br.com.gsistemas.core.propertie.JwtConfiguration;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

@RequiredArgsConstructor
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfiguration jwtConfiguration;

    @Override
    @SneakyThrows //Encapsula a excecao em uma runtimeException
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("Attempting authentication . . .");

        ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

        if (applicationUser == null){
            throw new UsernameNotFoundException("Unable to retrive the username or password.");
        }

        log.info("Creating the authentication object for te user '{}'and calling UserDetailServiceImp loadUserByUsername", applicationUser.getUsername());

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword(), emptyList());
        usernamePasswordAuthenticationToken.setDetails(applicationUser);

        return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        log.info("Authentication was successful for the user '{}', generating JWE token", auth.getName());

        SignedJWT signedJwt = createSignedJwt(auth);

        String encryptedToken = encryptToken(signedJwt);

        log.info("Token generated successfully, adding it to the response header");

        //Adicionado para evitar problemas no JS para pegar o header. Habilita o JS para pegar esses dois vlaores
        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN "+jwtConfiguration.getHeader().getName());

        response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptedToken);
    }

    //Pode-se usar o nimbus-jose ou jjwt, ambos fazem a mesma coisa porém o nimbus tem mais recursos como criptografia, etc
//    Ordem: Assinar depois criptografar o token
    @SneakyThrows
    private SignedJWT createSignedJwt(Authentication auth) {
        log.info("Starting to create the signed JWT");
        ApplicationUser applicationUser = (ApplicationUser) auth.getPrincipal();

        JWTClaimsSet jwtClaimSet = createJWTClaimSet(auth, applicationUser);

        //Criar chaves, gera uma publica e uma privada
        KeyPair keyPair = generateKeyPair();

        log.info("Building JWK from the RSA Keys");

        //Assinar
        JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256)
                .jwk(jwk) //Estamos passando a chave publica no header do jwt assinado para que os microservicos que utilizarem possam validar o token
                .type(JOSEObjectType.JWT)
                .build(), jwtClaimSet);

        log.info("Signing the token with the private RSA key");

        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());
        signedJWT.sign(signer);

        //Criptografar
        log.info("Serialized token {}", signedJWT.serialize());

        return signedJWT;
    }

    /**
     * Como a applicacao é STATELESS, ou seja, nao mantém estado do usuário, é necessário
     * passar nas claims os dados que serão necessários para os outros servicos.
     */
    private JWTClaimsSet createJWTClaimSet(Authentication auth, ApplicationUser applicationUser) {
        log.info("Creating the JWTClaimSet Object for '{}'", applicationUser);

        return new JWTClaimsSet.Builder()
                .subject(applicationUser.getUsername())
                .claim("authorities", auth.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(toList()))   //Customizada pois será utilizada em outros microservicos
                .issuer("http://academy.devdojo")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 100)))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair() {
        log.info("Generating RSA 2048 bits key");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.genKeyPair();
    }

    private String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encryptToken method");
        DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivateKey().getBytes());

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                .contentType("JWT")
                .build(), new Payload(signedJWT));

        log.info("Encrypting token with system's private key");

        jweObject.encrypt(directEncrypter);

        log.info("Token encrypted");

        return jweObject.serialize();
    }
}
