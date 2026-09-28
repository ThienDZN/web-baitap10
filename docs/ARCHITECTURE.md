# Kien truc

## 1. Luong du lieu

### 1.1 Dang ky

```
Browser /register
  -> POST /auth/signup  { fullName, email, password }
       -> AuthenticationController.register()
            @Valid RegisterUserModel              (jakarta.validation)
            -> AuthenticationService.signup()
                 - chuan hoa email (trim + lowercase)
                 - kiem tra trung email -> EmailAlreadyUsedException (409)
                 - BCryptPasswordEncoder.encode(password)
                 - UserRepository.save()
       <- 200 { id, fullName, email, images, role, createdAt }     (DTO, KHONG co password)
```

### 1.2 Dang nhap - sinh JWT

```
Browser /login
  -> POST /auth/login { email, password }
       -> AuthenticationController.authenticate()
            -> AuthenticationService.authenticate()
                 -> AuthenticationManager.authenticate(UsernamePasswordAuthenticationToken)
                      -> DaoAuthenticationProvider
                           -> UserDetailsService (ApplicationConfiguration) -> UserRepository.findByEmail
                           -> BCryptPasswordEncoder.matches(...)
                      -> sai thong tin: BadCredentialsException (401)
            -> JwtTokenService.generateToken(user)
                 new JWTClaimsSet.Builder()
                    .subject(email)
                    .issuer(...)
                    .issueTime(now)
                    .expirationTime(now + security.jwt.expiration-time)
                    .claim("authorities", ["ROLE_USER"])
                 -> new SignedJWT(new JWSHeader(HS256), claims).sign(new MACSigner(secret))
                 -> serialize()  =  "header.payload.signature"
       <- 200 { token, expiresIn, tokenType: "Bearer" }
  -> localStorage.setItem('token', ...)
  -> redirect /user/profile
```

### 1.3 Goi API duoc bao ve

```
Browser /user/profile
  -> GET /users/me   Header: Authorization: Bearer <token>
       |
       |  SecurityFilterChain (SecurityConfiguration)
       |    1. JwtAuthenticationFilter (dat TRUOC UsernamePasswordAuthenticationFilter)
       |         - khong co header Bearer  -> di tiep, khong xac thuc
       |         - co header Bearer:
       |             JwtTokenService.extractUsername(token)
       |                SignedJWT.parse(token)                -> ParseException        -> InvalidTokenException (401)
       |                kiem tra header.alg == HS256          -> sai                  -> InvalidTokenException (401)
       |                jwt.verify(new MACVerifier(secret))   -> false                -> InvalidTokenSignatureException (401)
       |                claimsVerifier.verify(claims, null)   -> ExpiredJWTException  -> TokenExpiredException (401)
       |                                                       -> BadJWTException     -> InvalidTokenException (401)
       |             UserDetailsService.loadUserByUsername(sub) -> UsernameNotFoundException (401)
       |             SecurityContextHolder.setAuthentication(...)
       |         - bat ky exception nao -> handlerExceptionResolver.resolveException(...)
       |    2. authorizeHttpRequests -> /users/** phai authenticated
       |    3. RestSecurityErrorHandler -> 401/403 dang JSON ProblemDetail
       |
       -> UserController.authenticatedUser()
            SecurityContextHolder.getContext().getAuthentication().getPrincipal()  -> User
            UserResponse.from(user)
       <- 200 { id, fullName, email, images, role, createdAt }
```

## 2. Trach nhiem tung module

| Module | Trach nhiem | Phu thuoc |
|---|---|---|
| `entity/User` | Anh xa bang `users`, dong thoi la `UserDetails` cua Spring Security | JPA |
| `repository/UserRepository` | Truy van `findByEmail`, `existsByEmail` | JPA |
| `models/*` | DTO vao/ra cua API, tach khoi entity de khong lo du lieu nhay cam | - |
| `service/JwtTokenService` | **Noi duy nhat** biet den Nimbus: ky, parse, verify, kiem tra claim | Nimbus |
| `service/AuthenticationService` | Dang ky (hash mat khau) + dang nhap (uy quyen cho `AuthenticationManager`) | `JwtTokenService` khong nam trong day |
| `service/UserService` | Truy van danh sach nguoi dung | Repository |
| `security/JwtAuthenticationFilter` | Doc header `Authorization`, goi `JwtTokenService`, thiet lap `SecurityContext` | `JwtTokenService`, `UserDetailsService` |
| `security/RestSecurityErrorHandler` | Tra 401/403 JSON khi request bi tu choi truoc controller | Jackson |
| `config/SecurityConfiguration` | Chinh sach truy cap, CORS, CSP, stateless session, dang ky filter | `JwtAuthenticationFilter` |
| `config/ApplicationConfiguration` | `UserDetailsService`, `PasswordEncoder`, `AuthenticationManager`, `AuthenticationProvider` | Repository |
| `exception/GlobalExceptionHandler` | Anh xa exception -> ma HTTP + ProblemDetail | - |
| `controller/*` | Mong, chi dieu phoi: goi service, tra DTO | service |

**Nguyen tac:** chi `JwtTokenService` duoc import `com.nimbusds.*`. Muon doi sang thu vien JWT khac
chi can sua 1 file nay (va cac exception tuong ung).

## 3. Vi sao chi mot writer cho lop token

`JwtTokenService` la diem duy nhat quyet dinh token hop le hay khong. Moi thay doi ve bao mat
(thuat toan, thoi han, claim bat buoc, clock skew) chi can sua o day, va duoc bao phu boi
`JwtTokenServiceTest`.

## 4. Cau hinh

| Property | Mac dinh | Y nghia |
|---|---|---|
| `security.jwt.secret-key` | gia tri mau (chi de chay bai tap) | Khoa HS256, toi thieu 32 byte. Dat qua `JWT_SECRET_KEY` |
| `security.jwt.expiration-time` | `3600000` (1 gio) | Thoi han token, millisecond |
| `security.jwt.issuer` | `jwt-nimbus-demo` | Claim `iss` |
| `app.cors.allowed-origins` | `http://localhost:8005` | Origin duoc phep |
| `spring.h2.console.enabled` | `true` | Bat H2 console (chi dev) |
| `app.demo-user.*` | tat | Tao tai khoan demo, mat khau lay tu bien moi truong |
