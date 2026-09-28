# Doi chieu JJWT (bai giang) - Nimbus JOSE+JWT (project nay)

Bai giang dung **JJWT 0.12.6** (`io.jsonwebtoken`). Project nay dung **Nimbus JOSE+JWT 10.10**
(`com.nimbusds:nimbus-jose-jwt`). Tai lieu nay ghi lai tung thay doi API, kem bang chung da kiem chung.

## 1. Dependency

**Bai giang (`pom.xml`)**

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.6</version>
</dependency>
```

**Project nay (`pom.xml`)** - chi 1 dependency:

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>10.10</version>
</dependency>
```

> **FACT (da kiem chung):** `mvn dependency:tree -Dincludes=com.nimbusds` trong project nay cho ket qua
> `com.nimbusds:nimbus-jose-jwt:jar:10.10:compile`.
> Canh bao lien quan: `spring-security-oauth2-jose` (6.4.2/6.5.0) keo theo **nimbus 9.37.3**.
> Project nay **khong** dung `spring-boot-starter-oauth2-resource-server` nen khong bi ghi de version.
> Neu sau nay them dependency do, phai khai bao nimbus 10.10 trong `<dependencyManagement>`.

Voi HS256, Nimbus **khong can** BouncyCastle hay thu vien nao khac (da kiem chung bang cach chay
chuong trinh chi voi 1 jar `nimbus-jose-jwt-10.10.jar` tren classpath).

## 2. Bang doi chieu API

| Cong viec | JJWT (bai giang) | Nimbus (project nay) |
|---|---|---|
| Tao header + thuat toan | `.signWith(getSignInKey(), Jwts.SIG.HS256)` | `new JWSHeader(JWSAlgorithm.HS256)` |
| Tao claims | `Jwts.builder().claims(...).subject(...)` | `new JWTClaimsSet.Builder().claim(...).subject(...)` |
| Doi tuong token | builder noi tiep | `new SignedJWT(header, claims)` |
| Tao khoa tu secret | `Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret))` | `new MACSigner(secretKey.getBytes(UTF_8))` |
| Ky | `.signWith(...).compact()` | `jwt.sign(signer); jwt.serialize()` |
| Parse | `Jwts.parser().verifyWith(key).build().parseSignedClaims(token)` | `SignedJWT.parse(token)` |
| Doi tuong xac thuc | nham trong parser | `new MACVerifier(secretKey.getBytes(UTF_8))` |
| Kiem tra chu ky | tu dong khi parse, sai thi nem `SignatureException` | `jwt.verify(verifier)` tra ve **`boolean`** |
| Lay claims | `.getPayload()` | `jwt.getJWTClaimsSet()` |
| Lay `sub` | `claims.getSubject()` | `claims.getSubject()` |
| Kiem tra het han | **tu dong** khi parse, nem `ExpiredJwtException` | **KHONG tu dong** - phai goi `DefaultJWTClaimsVerifier` |

## 3. Bon khac biet de gay loi nhat (da kiem chung thuc nghiem)

### 3.1 `SignedJWT.verify(...)` chi kiem tra chu ky, **khong** kiem tra `exp`

Chay chuong trinh that voi token da het han nhung chu ky dung:

```
[6] expired.verify(signature) = true      <-- chu ky VAN hop le
    expired -> com.nimbusds.jwt.proc.ExpiredJWTException: Expired JWT
```

Tai lieu chinh thuc cua connect2id cung ghi: *"Note that the SignedJWT.verify method only checks the
validity of the signature. The claims ... must therefore be subsequently checked by your application code."*

=> Trong `JwtTokenService.parseAndValidate()`, sau khi verify chu ky **bat buoc** phai goi them
`claimsVerifier.verify(claims, null)`. Neu quen buoc nay, token het han van duoc chap nhan.

### 3.2 `DefaultJWTClaimsVerifier` mac dinh **khong bat buoc** phai co `exp`

```
[9] missing exp ACCEPTED (note: DefaultJWTClaimsVerifier does not require exp by default)
```

=> Token khong co `exp` se **khong bao gio het han**. Project nay truyen
`requiredClaims = Set.of("exp")`:

```java
this.claimsVerifier = new DefaultJWTClaimsVerifier<>(
        NO_EXACT_MATCH_CLAIMS, Set.of(CLAIM_EXPIRATION));   // bat buoc phai co "exp"
```

### 3.3 Sai chu ky tra ve `false`, khong nem exception

```
[4] verify(wrong secret) = false
[5] verify(tampered)     = false
```

=> Phai kiem tra gia tri tra ve, va tu nem `InvalidTokenSignatureException` de tang web anh xa
thanh HTTP 401 (tuong duong `SignatureException` cua JJWT).

### 3.4 `SignedJWT.parse()` "de tinh" - parse thanh cong **khong** co nghia la token hop le

`SignedJWT.parse("eyJhbGciOiJIUzI1NiJ9.@@@.xxx")` van parse duoc (phan chu ky khong phai Base64URL hop le).
=> Khong duoc coi "parse duoc" la "hop le"; luon phai goi `verify(...)` va kiem tra `boolean`.

## 4. Loi cua `MACSigner` khi secret qua ngan

```
[10] short secret -> KeyLengthException: The secret length must be at least 256 bits
```

HS256 yeu cau khoa >= 256 bit (32 byte). `JwtTokenService` kiem tra truoc va nem
`IllegalStateException` voi thong bao ro rang ngay khi khoi dong, thay vi de loi xay ra luc dang nhap.

**Luu y ve cach dien giai secret:** `MACSigner(String)` / `MACVerifier(String)` dung **byte UTF-8**
cua chuoi. Gia tri mau trong bai giang `3cfa76ef...e007b` (64 ky tu) => 64 byte = 512 bit, hop le.
Trong bai giang, `Decoders.BASE64.decode(secretKey)` duoc ap len mot chuoi hex; project nay khong lam
vay ma dung truc tiep byte UTF-8 de ro rang, de kiem tra do dai.

**Luu y ve khoa mac dinh:** bai giang (va ban dau cua project nay) dat khoa ky ngay trong
`application.properties`. Do la **lo hong that**: bat ky ai doc duoc source deu ky duoc token gia mao
bat ky nguoi dung nao (da duoc kiem chung bang cach ky token va goi API thanh cong). Project nay
**khong con khoa mac dinh**: neu khong dat `JWT_SECRET_KEY`, ung dung tu sinh khoa ngau nhien 256 bit
va luu vao `.jwt-secret-key` (quyen 600). Xem `docs/SECURITY-REVIEW.md` muc 3.3.

## 5. Bang anh xa exception

| Tinh huong | JJWT (bai giang) | Nimbus (thuc te) | Exception cua project |
|---|---|---|---|
| Token sai dinh dang | `MalformedJwtException` | `java.text.ParseException` | `InvalidTokenException` |
| Sai thuat toan (`alg=none`, `RS256`) | `UnsupportedJwtException` | khong nem - phai tu kiem tra `header.getAlgorithm()` | `InvalidTokenException` |
| Sai chu ky | `SignatureException` | `verify()` tra ve `false` | `InvalidTokenSignatureException` |
| Het han | `ExpiredJwtException` | `com.nimbusds.jwt.proc.ExpiredJWTException` | `TokenExpiredException` |
| Thieu/sai claim khac (`nbf`, `exp`) | - | `com.nimbusds.jwt.proc.BadJWTException` | `InvalidTokenException` |
| Loi crypto noi bo | `JwtException` | `com.nimbusds.jose.JOSEException` | `TokenGenerationException` / `InvalidTokenException` |

> **Phien ban:** `ExpiredJWTException` (trong `com.nimbusds.jwt.proc`) chi co tu Nimbus **10.1**.
> Project nay pin 10.10 nen dung duoc. Neu bi ha version xuong 9.x, phai bo nhanh `catch` rieng cho
> `ExpiredJWTException` va chi bat `BadJWTException`.

## 6. Bang chung kiem chung

Tat ca ket luan tren duoc kiem chung bang 2 cach doc lap:

1. `javap -classpath nimbus-jose-jwt-10.10.jar <fqcn>` tren jar that tai tu Maven Central.
2. Chuong trinh `NimbusProbe` chay that voi classpath chi gom 1 jar, in ra 11 ket qua
   (ky, verify dung/sai khoa, sua token, het han, thieu `exp`, `nbf` tuong lai, khoa ngan, token rac).

Trich xuat trong tai lieu nay la output thuc te cua lan chay do.
