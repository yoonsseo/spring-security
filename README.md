# 📌 spring-security
## 1. 인증과 인가
### 🔐 인증 Authentication
* **증명하다**라는 의미로, 예를 들어 아이디와 비밀번호를 이용하여 로그인 하는 과정


* 해당 사용자가 **본인이 맞는지** 확인하는 과정

### ✅ 인가 Authorization
* **권한부여**나 **허가**와 같은 의미로 사용되고, 어떤 대상이 특정 목적을 실현하도록 허용(Access) 하는 것 의미  


* 해당 사용자가 요청하는 자원을 실행할 수 있는 **권한이 있는가**를 확인하는 과정

### 👻 Credential 기반의 인증 방식
* Spring Security는 인증과 인가를 위해 `Principal`을 아이디로, `Credential`을 비밀번호로 사용하는   
  사용자 자격 증명 Credential 기반의 인증 방식을 사용한다 


* `Principal(접근 주체)` : 보호받는 Resource에 접근하는 대상
 

* * `Credential(비밀번호)` : Resource에 접근하는 대상의 비밀번호

### 🌐 Spring Security Architecture
![Spring Security Architecture](https://github.com/yoonsseo/spring-security/assets/90557277/7d8cc2c4-3a4b-4a0c-9c5b-91b94ef0d0ba)
> 1. `Http Request` - 사용자가 로그인 정보와 함께 인증 요청 
> 
> 
> 2. `AuthenticationFilter`가 요청을 가로채고,  
>    가로챈 정보를 통해 `UsernamePasswordAuthenticationToken`이라는 인증용 객체 생성해서  
> 
> 
> 3. `AuthenticationManager`의 구현체인 `ProviderManager`에게 생성한 `UsernamePasswordAuthenticationToken` 객체 전달
> 
> 
> 4. `AuthenticationManager`는 등록된 `AuthenticationProvider`들을 조회하고 인증 요구  
> 
> 
> 5. `AuthenticationProvider`는 실제 DB에서 사용자 인증정보를 가져오는 `UserDetailsService`에 사용자 정보를 넘겨준다
> 
> 
> 6. `UserDetailsService`는 `AuthenticationProvider`에게 넘겨받은 사용자 정보를 통해,  
>    DB에서 찾은 사용자 정보인 `UserDetails` 객체를 만든다
> 
> 
> 7. `AuthenticationProvider`들은 `UserDetails` 객체를 넘겨받고 사용자 정보 비교
> 
> 
> 8. 인증이 완료되면, 권한 등의 사용자 정보를 담은 `Authentication` 객체를 반환한다
> 
> 
> 9. 다시 최초의 `AuthenticationFilter`에 `Authentication` 객체가 반환되고  
> 
> 
> 10. `Authenticaton` 객체를 `SecurityContext`에 저장

#### 1. Authentication
  * 현재 접근하는 주체의 정보와 권한을 담는 인터페이스


  * `Authentication` 객체는 `SecurityContext`에 저장되며,    
    `SecurityContextHolder`를 통해 `SecurityContext`에 접근하고,  
    `SecurityContext`를 통해 `Authentication`에 접근할 수 있다  

#### 2. UsernamePasswordAuthenticationToken
* `Authentication`을 implements한 `AbstractAuthenticationToken`의 하위 클래스  
  즉, `Authentication`의 구현체이고, 그래서 `AuthenticationManager`에서 인증과정을 수행할 수 있다  
* 추후 인증이 끝나고 `SecurityContextHolder`에 등록될 `Authentication` 객체


* User의 ID를 `Principal` 로, Password를 `Credential`로 생성한 인증 개체
  > 여기에서 말하는 `Principal` 역할을 하는 User의 ID 또는 Username은 로그인 시 ID와 PW의 ID를 똣한다  
  > 로그인 시 email을 ID로 사용한다면 email이, 전화번호를 ID로 사용한다면 전화번호가 곧 Username이 된다 
  
* `UsernamePasswordAuthenticationToken`의 첫 번째 생성자는 인증 전의 객체를 생성하고,  
  두 번째는 인증이 완료된 객체를 생성한다
```java
public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
	super(null);
	this.principal = principal;
	this.credentials = credentials;
	setAuthenticated(false);
}
public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
		Collection<? extends GrantedAuthority> authorities) {
	super(authorities);
	this.principal = principal;
	this.credentials = credentials;
	super.setAuthenticated(true); // must use super, as we override
}
```

#### 3. AuthenticationManager
* 만들어진 `UsernamePasswordAuthenticationToken`은 `AuthenticationManager`의 인증 메소드를 호출하는 데 사용된다
* 인증에 대한 부분은 `AuthenticationManager`를 통해서 처리하게 되는데,  
  실질적으로는 `AuthenticationManager`에 등록된 `AuthenticationProvider`에 의해 처리된다
* 인증에 성공하면 두 번째 생성자를 이용해 객체를 생성하여 `SecurityContext`에 저장한다

#### 4. AuthenticationProvider
* `AuthenticationManager`의 구현체 
* `AuthenticationProvider`에서는 **실제 인증에 대한 부분을 처리**하는데,  
  인증 전의 `Authentication` 객체를 받아서 인증이 완료된 객체를 반환하는 역할을 한다
* Custom한 `AuthenticationProvider`를 작성하고 `AuthenticationManager`에 등록하면 된다

#### 5. ProviderManager
* `AuthenticationManager`를 implements한 구현체 `ProviderManager`는  
  `AuthenticationProvider`를 구성하는 목록을 갖는다

#### 6. UserDetailsService
```java 
public interface UserDetailsService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```
* Spring Security의 **interface**이고, 구현체는 **직접 개발**해야한다 (customize)
* `username`을 기반으로 검색한 `UserDetails` 객체를 반환하는 하나의 메소드 `loadUserByUsername` 만을 가지고 있고,
  일반적으로 이를 implements한 클래스에 `UserRepository`를 주입받아 DB와 연결하여 처리한다
* `UserDetailsService`는 DB에 저장된 회원의 비밀번호와 비교하고,  
  일치하면 `UserDetails` 인터페이스를 구현한 객체를 반환한다

#### 7. UserDetails
* 인증에 성공하여 생성된 `UserDetails` 객체는 `Authentication` 객체를 구현한 `UsernamePasswordAuthenticationToken`을 생성하기 위해 사용된다

#### 8. SecurityContextHolder
* 보안 주체의 세부 정보를 포함하여 응용프로그램의 현재 보안 컨텍스트에 대한 세부 정보가 저장된다
* `SecurityContextHolder`는 `ThreadLocal`에 저장되어, `Thread`별로 `SecurityContextHolder` 인스턴스를 가지고 있기 때문에,  
  사용자 별로 `Authentication` 객체를 가질 수 있다 

#### 9. SecurityContext
* 인증된 사용자 정보 `Authentication`을 보관하는 역할 
* `SecurityContext를` 통해 `Authentication`을 저장하거나 꺼내올 수 있다
```java
SecurityContextHolder.getContext().setAuthentication(authentication);
SecurityContextHolder.getContext().getAuthentication(authentication);
```

#### 👀 그래서 우리가 사용할 `Authentication` 객체는?  
→ `UsernamePasswordAuthenticationToken` 객체 

#### 10. GrantedAuthority
* 현재 사용자(Principal)가 가지고 있는 권한 의미
* `ROLE_ADMIN`이나 `ROLE_USER`와 같이 `ROLE_*`의 형태로 사용한다
* `GrantedAuthority` 객체는 `UserDetailsService`에 의해 불러올 수 있고,  
* 특정 자원에 대한 권한이 있는지 검사해 접근 허용 여부를 결정한다



## 2. 스프링 시큐리티 설정
### 2.1. `SecurityFilterChain` 설정 
> **변경**  
> 스프링 부트 3.0 이상부터 스프링 시큐리티 6.0.0 이상의 버전이 적용되며  
> Deprecated된 코드 변경 

#### 2.1.1. 
```java
//.httpBasic().disable()
.httpBasic(HttpBasicConfigurer::disable)
```
* UI쪽으로 들어오는 설정
* Http basic Auth 기반으로 로그인 인증창이 뜨는데, JWT를 사용할 거라 뜨지 않도록 설정   
  \+ `formLogin.disable()` : formLogin 대신 JWT를 사용하기 때문에 disable로 설정


#### 2.1.2. 
```java
//.csrf.disable()
//.cors().and()
.csrf(AbstractHttpConfigurer::disable)
.cors(Customizer.withDefaults())
```
* API를 작성하는데 프런트가 정해져있지 않기 때문에 csrf 설정 우선 꺼놓기
#### CSRF 
  * **Cross Site Request Forgery**  : 사이트 간 위조 요청
  * 웹 사이트 취약점 공격 방법 중 하나로, 사용자가 자신의 의지와는 무관하게 공격자가 의도한 행위를 특정 웹 사이트에 요청하게 하는 공격
  * Spring Security에서는 CSRF에 대한 예방 기능을 제공한다
  * **근데 이 좋은 기능을 왜 disable?**
    * 스프링 시큐리티 문서에서는 일반 사용자가 브라우저에서 처리할 수 있는 모든 요청에 CSRF 보호를 사용할 것을 권장하고,  
      브라우저를 사용하지 않는 클라이언트만 사용하는 서비스를 만드는 경우 CSRF 보호를 비활성화하는 것이 좋다고 함
    * 여기에서 브라우저를 사용하지 않는 클라이언트만 사용하는 서비스 → 대부분의 REST API 서비스라고 이해함  
      즉 대부분의 가이드는 REST API 서버 기준으로 disable을 적용하고 있다
#### CORS
  * **Cross-Origin Resource Sharing** : 서로 다른 Orgin 간의 상호작용 시 브라우저에서 이를 중지하기 위해 제공하는 기본 보호 기능, 프로토콜
  * HTTP 요청은 기본적으로 Cross-Site HTTP Requests가 가능 (다른 도메인 사용 가능)   
    하지만 Cross-Site HTTP Requests는 Same Origin Policy를 적용받기 때문에,  
    프로토콜, 호스트명, 포트가 같아야만 요청이 가능하다
  * `cors()`로 cors에 대한 커스텀 설정 허용
    * `addAllowedOrigin()` : 허용할 URL 설정
    * `addAllowedHeader()` : 허용할 Header 설정
    * `addAllowedMethod()` : 허용할 Http Method 설정


#### 2.1.3. 
```java
//.authorizeRequests()
//.requestMatchers("/api/**").permitAll()
//.requestMatchers("/api/**/users/join", "/api/**/users/login").permitAll()
.authorizeHttpRequests(authorize -> authorize
    .requestMatchers("/api/**").permitAll()
    .requestMatchers("/api/v1/users/join", "/api/v1/users/login").permitAll())
```
* 특정한 경로에 특정한 권한을 가진 사용자만 접근할 수 있도록 하는 설정
* `authorizeRequests()` : 시큐리티 처리에 HttpServletRequest를 이용한다는 것, 각 경로별 권한 처리 
* `requestMatchers()` : 특정한 경로 지정
  * 만약 spring-security 5.8 이상의 버전을 사용하는 경우에는  
    `antMatchers`, `mvcMatchers`, `regexMatchers`가 더 이상 사용되지 않기 때문에,   
    `requestMatchers`를 사용해야 한다고 함
  > __URL 패턴 `/*` 과 `/**`__  
  >
  > * __`/*`__ : 경로의 바로 하위에 있는 모든 경로 매핑  
  > 
  >ex. `AAA/*` : `AAA/BBB`, `AAA/CCC` 해당, `AAA/BBB/CCC` 해당하지 않음    
  > * __`/**`__ : 경로의 모든 하위 경로(디렉토리) 매핑  
  > 
  >ex. `AAA/**` : `AAA/BBB`, `AAA/CCC`, `AAA/BBB/CCC`, `AAA/.../.../DDD/...`, `AAA/BBB/CCC/.../.../...` 전부 해당  

* `permitAll()` :  모든 사용자가 인증 절차 없이 접근할 수 있음
* `authenticated()` : 인증된 사용자만 접근 가능   
* `hasRole()` : 시스템 상에서 특정 권한을 가진 사람만이 접근할 수 있음
* `anyRequest().authenticated()` : 나머지 모든 리소스들은 무조건 인증을 완료해야 접근이 가능하다는 의미


#### 2.1.4. 
```java
//.sessionManagement()
//.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
.sessionManagement((sessionManagement) -> sessionManagement
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
```
* 스프링 시큐리티는 기본적으로 session을 사용해 웹을 처리하는데,  
  JWT를 사용하기 때문에 session을 stateless로 설정, 세션 사용하지 않음


### 2.2. `BCryptPasswordEncode` 설정
#### 🪢 **`BCryptPasswordEncode`**
* Spring Seurity 프레임워크에서 제공하는 클래스 중 하나로 비밀번호를 암호화하는 데 사용할 수 있는 메서드를 가진 클래스  
#### 🔒 **`BCryptPasswordEncoder.encode(CharSequence rawPassword)`**
* 패스워드를 암호화해주는 메서드, `String` 반환  
* 똑같은 비밀번호를 인코딩하더라도 매번 다른 문자열을 반환한다 
#### 🗝️ **`matches(CharSequence rawPassword, String encodedPassword)`** 
* 제출된 인코딩 되지 않은 패스워드(일치 여부를 확인하고자 하는 패스워드)와 인코딩 된 패스워드의 일치 여부 확인
* 첫 번째 파라미터로 일치 여부를 확인하고자 하는 인코딩 되지 않은 패스워드,  
두 번째 파라미터로 인코딩된 패스워드 입력
* `boolean` 반환 
 
## 🚨 Spring Security 테스트 하기
### 1. 의존성 추가 🐘
```java
testImplementation 'org.springframework.security:spring-security-test'
```
### 2. 인증 정보 미리 주입하기 💉
#### 2.1. SecurityContext에 직접 Authentication 주입
#### 2.2. @WithMockUser
* 테스트에 필요한 **인증된 인증 정보**를 제공하며 간단한 정보를 기본으로 설정할 수 있게 도와준다
* 미리 인증된 사용자를 만들어놓지 않아도 간단하게 인증이 필요한 메소드를 테스트할 수 있다
* `userName`, `password`, `role` 등을 어노테이션 value를 통해 설정해줄 수 있고,  
  default value로 `username = "user"`, `password = "password"`, `role = "USER"`가 설정되어 있다
* 테스트 시 필요한 정보가 인증여부 정도거나, 사용자 이름 등과 같이 간단한 것이라면  
  `@WithMockUser`를 통해 간단히 테스트 가능
#### 2.3. @WithAnonymousUser
* 테스트 진행 시 `@WithMockUser`를 통해 **인증된 사용자 정보**를 간단히 주입해주었다면,  
  반대로 `@WithAnonymousUser`는 **인증되지 않은 사용자**에 대한 테스트 시 이용

### 3. csrf 설정해주기
```java
mockMvc.perform(post("/api/v1/users/login")
        .with(csrf())
        .contentType(MediaType.APPLICATION_JSON)
        .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
    .andDo(print())
    .andExpect(status().isUnauthorized());
```
* 테스트로 호출하면 스프링 시큐리티가 csrf라고 판단하기 때문에 `.with(csrf())` 꼭 처리 해주어야 한다
* `MockMvc`에서 `request`에 자동으로 valid한 `CsrfToken` 제공 
#### csrf 처리 전
![csrf 처리 전](https://github.com/yoonsseo/spring-security/assets/90557277/c8a16d1a-21c2-4cd1-9b7c-4402e3f82e6f)
#### csrf 처리 후
![csrf 처리 후](https://github.com/yoonsseo/spring-security/assets/90557277/1d8beb47-0487-4ac3-a63c-1fedc3dc17e1)

## 4. JWT - JWT TOKEN 발행
### 🛡️ JWT : Json Web Token
* 서로 다른 기기에 데이터를 전달할 때 사용하는 방법 중 하나로, `Base64`의 형태를 가진다 
* `Header`와 `Body(또는 Payload)`, 그리고 `Signature` 세 부분으로 나눠진다  
#### 📑 Header
* JWT의 metadata들을 나타낸다  
* Sign에 사용된 Algorithms, format, 그리고 ContentType 등의 정보
#### 📄 Payload (Body)
* `Claim` 단위로 저장
> **Claim**
>  * 사용자의 속성이나 권한, 정보의 한 조각 또는 Json의 필드라고 생각하면 된다 
>  * `Claim`에는 JWT 생성자가 원하는 정보들을 자유롭게 담을 수 있는데  
> Json 형식을 가지고 있기 때문에 단일 필드도 가능하고,  
> Object와 같은 complexible한 필드도 추가할 수 있다  
> 
>   ```java
>    Claims claims = Jwts.claims(); //일종의 Map
>    claims.put("userName", userName);
>    ...
>        Jwts.builder()
>                .setClaims(claims)
>                ...
>    ```
> * Claim에 userName을 담아두면 따로 사용자 id를 입력받지 않아도 토큰에 들어있는 값을 꺼낼 수 있다 
 


#### 📝 Signature
* Header와 Body는 Base64 형태로 인코딩되어 암호화되어 있지 않은데  
  공격자가 내용을 바꿀 수가 있다
* Signature로 서명을 통해 암호화 과정을 거친다
* 서명 이후 Header와 Body의 내용이 바뀐다면 Signature의 결과값이 바뀌어 받아들여지지 않는다

### 4.1. 의존성 추가 🐘
```java
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
```
* JWT 라이브러리의 핵심 API를 제공하고 JWT의 생성 및 검증을 다룰 수 있다
```java
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
```
* `jjwt-impl` 의존성을 추가하지 않은 채 `Jwts.builder()` 를 호출하게 되면 오류가 발생한다

```java
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```
* `jjwt-impl`의 구현체 라이브러리로, `jjwt-jackson` 외에도 `jjwt-gson`이 있다  
* `jjwt-jackson` 의존성을 추가하지 않으면 `compact` 메서드를 처리하던 도중 오류가 발생한다  
  → `jjwt-impl`에서 구현체를 찾아보지만 없기에 오류가 발생 

#### 의존성을 세 개나 추가해야 하는 이유는?
> `jjwt-api` 는 패키지 관리에 있어서 `implemenation` 과 `runtimeonly` 로 구분하여 의존성 추가를 권장하고 있다   
> 경고 없이 언제든 변할 수 있는 패키지는 `runtimeonly`로 관리하고 그렇지 않은 것은 `implemenation`으로 관리해   
> 안정적으로 `jjwt-api` 라이브러리를 사용하겠다는 의도   
> 즉, `jjwt-impl`, `jjwt-jackson` 또는 `jjwt-gson` 은 경고없이 언제든 변화할 수 있고   
> `jjwt-api`는 하위호환성을 맞춰가며 개발한다는 의미   
> 실제로 코드를 보면서 하위호환성에 대한 언급과 `@Deprecated`를 통해 코드를 유지하려는 노력을 살펴볼 수 있다 

### 4.2. JWT 생성 시 필요한 정보
#### Jwts 클래스
* JWT 인스턴스를 생성하는 역할을 하는 팩토리 클래스 

#### 4.2.1. `Jwts.builder()`
```java
public static String createToken(String userName, Key key, long expireTimeMs) {
    Claims claims = Jwts.claims(); //일종의 Map
    claims.put("userName", userName);

    return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + expireTimeMs))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact();
}
```
0. Header 설정
   * `.setHeaderParam("key", "value")` 또는 `.setHeader(header)`와 같은 방식 사용 가능 

##### Body(Payload) 설정 
1. `setClaims()` : JWT에 포함시킬 Custom Claims 추가 - 주로 인증된 사용자 정보
    * `.claim("key", "value")` 또는 `.setClaims(claims)`와 같은 방식 사용 가능
   
2. `setSubject()` : JWT에 대한 제목 
   

3. `setIssuedAt()` : JWT 발행 일자 - 파라미터 타입은 `java.util.Date`
    

4. `setExpiration()` : JWT의 만료기한 - 파라미터 타입은 `java.util.Date`  


5. `signWith()` : 서명을 위한 `Key(java.security.Key)` 객체 설정
    ```java
    //.signWith(SignatureAlgorithm.HS256, key)
    .signWith(key, SignatureAlgorithm.HS256)
    ```
    ##### `signWith(io.jsonwebtoken.SignatureAlgorithm, java.lang.String)' is deprecated`  
   * 특정 문자열(String)이나 byte를 인수로 받는 메서드로 사용이 중단되었는데,  
     많은 사용자가 안전하지 않은 원시적인 암호 문자열을 키 인수로 사용하려고 시도하며 혼란스러워했기 때문이라고 한다 
    ##### `signWith(java.security.Key key, io.jsonwebtoken.SignatureAlgorithm alg)`
   * `String`이 아니라 `Key` 값을 생성하고 서명을 진행해야 한다


6. `compact()` : JWT 생성하고 직렬화 


### 4.3. Secret Key 생성하기 
#### 👀 Secret Key 란? 
토큰을 생성하기 위한 Key 

#### 코드
```java
String keyBase64Encoded = Base64.getEncoder().encodeToString(key.getBytes());
SecretKey key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
```
* 사용하고자 하는 `plain secretKey`(암호화 되지 않음, 첫 번째 줄의 `key`)를 `byte`배열로 변환해주고,  
* HMAC-SHA 알고리즘을 통해 암호화해주는 `Keys.hmacShaKeyFor`를 통해 암호화된 `Key` 객체로 만들어주는 코드 
#### **`io.jsonwebtoken.security.WeakKeyException`**
* `secretKey`가 **`256bit`보다 커야** 한다는 `Exception` - 알파벳 한 글자당 `8bit`이므로 **32글자 이상**이어야 한다는 뜻
* 한글은 한 글자 당 `16bit`인데 16글자이면 생성될까? → 생성된다

## 5. JWT - JWT 검증하기
> 1. `Jwts.parserBuilder()` 메소드로 `JwtParserBuilder` 인스턴스 생성
> 2. JWS 서명 검증을 위한 `SecretKey` 또는 `비대칭 공개키` 지정
>    > `TOKEN` 발급 시 사용했던 `secretKey`
> 3. `build()` 메소드를 호출하면 thread-safe한 `JwtParser`가 반환된다  
> 4. `parseClaimsJws(jwtString)` 메소드를 호출하면 오리지널 signed JWT가 반환된다  
> 5. 검증에 실패하면 `Exception` 발생

#### JWT TOKEN 파싱하기 
```java
Jws<Claims> jws = Jwts.parserBuilder()
        .setSigningKey(key)
        .build()
        .parseClaimsJws(token); 
```
* `parseClaimsJws(token)` 
  * 파라미터로 주어진 `JWT 토큰` 파싱
  * `JWT 토큰`의 구성 요소 Header, Body(Payload), Signature를 분석하고,  
    서명을 확인해 JWT의 무결성 검증
  * `JWT 토큰` 생성 시의 `Claim` 정보를 추출할 수 있다 
  

* `parseClaimsJwt()`
  * `parseClaimsJws()`가 아니라 `parseClaimsJwt()`를 사용하면 오류 발생
  * 처음에 `TOKEN`을 생성할 때 `signWith()`를 통해 **서명**을 했기 때문에  
    복호화 시에도 **서명에 대한 검증**을 진행해야 한다 
  * `parseClaimsJwt()`는 서명 검증 없이 단순히 헤더와 클레임만 추출한다 
  * `parseClaimsJwt()`를 사용하고 싶다면 `TOKEN` 생성 시 `signWith()`를 통해 서명에 대한 정보를 넘겨주지 않으면 된다  

```java
Claims claims = jws.getBody();
```
* `getBody()`
  * `TOKEN`의 `Claim` 정보 또는 토큰에 포함된 데이터,  
    즉, `TOKEN` 생성 시 포함한 사용자 정보, 권한, 만료 시간 등을 추출할 수 있다
  

* 이 외에도 `getHeader()`와 `getSignature()`를 통해 각각 `TOKEN`의 메타데이터와 서명을 추출할 수 있다 

#### Claim 추출하기
```java
String username = claims.get("username", String.class); // "username" 클레임 값 추출
String role = claims.get("role", String.class); // "role" 클레임 값 추출
Date expiration = claims.getExpiration();
Date issuedAt = claims.getIssuedAt();
```
* `get()`
  * 키와 값의 쌍으로 저장된 `Claim`은 키를 통해 값을 찾을 수 있다
  ```java
    public abstract <T> T get(String claimName, Class<T> requiredType)
  ```
  * `Claim` 키와 타입에 맞는 값 반환
  

* 이 외에도 `TOKEN` 만료 시간을 추출하는 `getExpiration()`이나  
  `TOKEN` 생성 시간을 추출하는 `getIssuedAt()` 등의 메소드가 있다  


## 🪪 회원가입 
>1. `POST` `/api/v1/users/join` 만들기   
>    - RequestBody - userName, password
>2. 회원가입 성공/실패 Controller Test
>3. `UserService.join()` - 중복 체크해서 `ifPresent`면 `RuntimeException` 리턴
>    - `@RestControllerAdvice` 선언
>    - `@ExceptionHandler`로 `RuntimeException` 받기
>4. `CuntomException`으로 변경
>    - ErrorCode 선언
>    - 중복 check exception 수정
>5. Spring Security 적용해보기
>    - Spring Security 넣고 join(추후 login도) 허용해주는 세팅
>    - BCryptPasswordEncoder 추가
>    - Join할 때 password Encoding해서 저장하기  

### 1. `User`, `UserRepository`, `UserService`, `UserController`, `JoinRequestDto` 생성
- `User` - id, name, password
- `JoinRequestDto` - userName, password  
- `UserService` - 이름 중복 체크(`ifPresent`로 `RunTimeException`) 후 저장
  * `isPresent` → true, false 체크  
  * `ifPresent` → 값을 가지고 있는지 확인 후 예외처리
```java
public String join(JoinRequestDto joinRequestDto) {
    //중복체크
    userRepository.findByName(joinRequestDto.getUserName())
        .ifPresent(user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED, "이미 있는 회원");});

    //저장
    userRepository.save(User.builder()
            .name(joinRequestDto.getUserName())
            .password(joinRequestDto.getPassword())
            .build());
    
    return "회원가입 성공";
}
```


### 2. `UserController`에 대한 `@WebMvcTest`
```java
@WebMvcTest
class UserControllerTest {
    @Autowired MockMvc mockMvc;
    @MockBean UserService userService;
    @Autowired ObjectMapper objectMapper;
    //자바 오브젝트를 JSON으로 만들어주는 잭슨의 오브젝트

    @Test
    @DisplayName("회원가입 성공")
    void join() throws Exception{
        //given
        String userName = "yoonsseo";
        String password = "1234";

        //when, then
        mockMvc.perform(post("/api/v1/users/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(new JoinRequestDto(userName, password)))) 
										//HttpRequest에 어떤 값을 보낼 때는 byte로 보낸다
                .andDo(print())
                .andExpect(status().isOk());
    }
}
```

### 3. `@RestControllerAdvice`를 통해 `@ExceptionHandler`로 특정 exception 처리 

```java
@RestControllerAdvice
public class ExceptionManager {
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> runtimeExceptionHandler(RuntimeException e) { 
		//? -> 리스펀스엔티티 바디에 뭐든지 들어갈 수 있다
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(e.getMessage());
    }
}
```

### 4. Custom Exception
```java
@AllArgsConstructor
@Getter
public class AppException extends RuntimeException {
    private ErrorCode errorCode;
    private String message;
}
```
```java
@AllArgsConstructor
@Getter
public enum ErrorCode {
    USERNAME_DUPLICATED(HttpStatus.CONFLICT, "");

    private HttpStatus httpStatus;
    private String message;
}
```
```java
@RestControllerAdvice
public class ExceptionManager {
    @ExceptionHandler(AppException.class)
    public ResponseEntity<?> appExceptionHandler(AppException e) { 
        return ResponseEntity.status(e.getErrorCode().getHttpStatus())
                .body(e.getErrorCode() + " " + e.getMessage());
                //리스펀스오브젝트로 랩핑을 할 수도 있는데 일단 이렇게 처리
    }
}
```

#### 포스트맨  
![회원가입 포스트맨](https://github.com/yoonsseo/spring-security/assets/90557277/99eb10eb-96dd-4292-865e-bc6089a38432)

### 5. Spring Security 적용
#### 5.1. 의존성 추가 🐘
```java
implementation 'org.springframework.boot:spring-boot-starter-security'
```
#### 5.2. `SecurityConfig` 설정 추가 
* 웹 설정을 extends 하던 방법이 있었는데, 스프링 부트 버전이 올라가면서  
  `@Bean`으로 `SpringFilterChain`을 재정의해서 이용하는 방법으로 바뀜  


* 시큐리티 적용 후 잘 되던 회원가입에 DENY가 뜬다 

![시큐리티 적용 DENY 포스트맨](https://github.com/yoonsseo/spring-security/assets/90557277/e2a18970-fc4a-495b-b123-7647b31ae6aa)

#### 5.3. `BCryptPasswordEncoder` 이용해 비밀번호 암호화해서 저장하기 
```java
//User Service
private final BCryptPasswordEncoder bCryptPasswordEncoder;
...
        
    //.password(joinRequestDto.getPassword())
    .password(bCryptPasswordEncoder.encode(joinRequestDto.getPassword()))
```
|적용 전|BCryptPasswordEncoder 적용 후|
|---|---|
|![인코딩 없이 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/b86eaf45-3d11-485d-a1f7-78a31be68674)|![인코딩 후 저장된 비밀번호 DB](https://github.com/yoonsseo/spring-security/assets/90557277/a6f62ddd-1955-4b7f-9a5a-d9521a230d6d)|
* 순환 참조 문제가 생길 수 있기 때문에 `SecurityConfig`와 `BCryptPasswordEncoder`는 꼭 다른 클래스에 선언해주어야 한다고 한다 

## 🔐 로그인 
>1. 로그인 테스트
>    - `Spring Security Test` 라이브러리 사용
>    - `with(csrf())`로 호출 
>2. 로그인 Service 구현  
>    - `login(String userName, String password)`
>    - 아이디 확인 → 비밀번호 확인 → TOKEN 발행 
>3. 로그인 시 Token 발행하기
>    - `JWT` 라이브러리 사용
>    - `jwt.token.secret = "secretKey"`
>    - `JWT_TOKEN_SECRET = "real_secret_key"`

#### 로그인이란?
아이디와 패스워드를 입력하면 `토큰`을 발행 해주는 것

### 1. 로그인/회원가입 - 스프링 시큐리티 테스트
* `@WithMockUser`, `.with(csrf())` 적용 
```java
@Test
@DisplayName("로그인 실패 - 아이디(이름) 없음")
@WithMockUser
void login_fail1() throws Exception {
    //given
    String userName = "hello";
    String password = "1234";

    //when, then
    when(userService.login(userName, password))
            .thenThrow(new AppException(ErrorCode.USER_NOT_FOUND, ""));

    mockMvc.perform(post("/api/v1/users/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(objectMapper.writeValueAsBytes(new LoginRequestDto(userName, password))))
            .andDo(print())
            .andExpect(status().isNotFound());
}
```

### 2. 로그인 Service 구현 : ID → PW (→ TOKEN 발행) 
#### 로그인 경우의 수 
1. 아이디와 패스워드 올바르게 입력 → `SUCCESS`
2. 아이디가 없는 경우 → `NOT_FOUND`
3. 비밀번호가 틀린 경우 → `UNAUTHORIZED`

### 3. 로그인 시 Token 발행하기
#### 3.1. 의존성 주입 🐘
```java
implementation 'io.jsonwebtoken:jjwt-api:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.11.5'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.11.5'
```
#### 3.2. SecretKey 등록
##### 3.2.1. [방법1] 환경 변수에서 넣어주기 
* 왼쪽 상단의 `Run` → `Edit Configurations` 또는 오른쪽 상단에서 다음과 같이 `Edit Configurations`
![환경변수등록1](https://github.com/yoonsseo/spring-security/assets/90557277/dacea8e3-0068-4400-900b-732c0a847603)
* 왼쪽 메뉴에서 `Spring Boot Application`으로 잘 접속되었나 확인 후   
  → 오른쪽 메뉴에서 `Environment variables`란이 없는 경우 `Modify options` → `Environment variables` 선택해서 환경변수 칸 추가
  ![환경변수등록2](https://github.com/yoonsseo/spring-security/assets/90557277/fbda65bf-a610-4df7-a24e-8e8eae976527)
  ![환경변수등록3](https://github.com/yoonsseo/spring-security/assets/90557277/7aebe1bc-d7d8-4c89-897d-1acd76953663)
* 환경 변수 옵션 칸에서 키-값 쌍을 직접 입력해주거나 오른쪽 아이콘을 눌러서 등록
    ![환경변수등록4](https://github.com/yoonsseo/spring-security/assets/90557277/030acec2-c913-4b4c-baa1-40a258a05e07)
 
##### 3.2.2. [방법2] yml에서 바로 넣어주어도 상관없다 
![yml-secret-key](https://github.com/yoonsseo/spring-security/assets/90557277/c640d87f-f463-4c4c-9881-c0dfd9065b33)

#### 3.3. `JwtTokenUtil` - `createToken` 작성
```java
public static String createToken(String userName, Key key, long expireTimeMs) {...}
```

#### 3.4. 'UserService' - `TOKEN` 발행 로직
* `yml`과 `환경변수`로 넣어준 `secretKey` 가져오기
```yaml
#application.yml
jwt:
  token:
    secret: "secretKey"
```
```java
//UserService
@Value("${jwt.token.secret}")
private String key;

//토큰 만료 시간 1초 * 60 * 60 = 1시간
private final static Long expireTimeMs = 1000 * 60 * 60L;
```

* 먼저, 사용하고자 하는 `plain secretKey`(암호화 되지 않음)를 `byte`배열로 변환해주고,  
  HMAC-SHA 알고리즘을 통해 암호화해주는 `Keys.hmacShaKeyFor`를 통해 암호화된 `Key` 객체로 만들어주기 
```java
String keyBase64Encoded = Base64.getEncoder().encodeToString(key.getBytes());
SecretKey key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
```

* `createToken`으로 토큰 생성해서 반환
```java
String token = JwtTokenUtil.createToken(userName, key, expireTimeMs);
```

#### 포스트맨
![로그인토큰반환](https://github.com/yoonsseo/spring-security/assets/90557277/b92b8a59-c8e4-43ef-95a1-706dfabc8acf)


## 🧿 인증과 인가 
> 0. `POST` `api/v1/reviews` EndPoint 만들기
> 1. 모든 `POST` 접근 막기   
>    - JwtFilter 인증 계층 추가하기  
>    - 모든 요청에 권한 부여하기
> 2. `TOKEN` 여부 확인 
>    - TOKEN 있으면 권한 부여 
>    - TOKEN이 없으면 권한 부여하지 않기
> 3. `TOKEN` 유효성 검증 
>    - TOKEN의 유효시간이 지났는지 확인하기  
> 4. `TOKEN`에서 userName(id) 꺼내서 Controller에서 사용하기  
    
### 1. 모든 요청에 권한 부여하기 
#### 1.1. API 요청에 대해 접근 권한 설정  
앞서 로그인에서 설정했던 `SecurityConfig`의 `SecurityFilterChain` 재정의 이용  
→ `AuthenticationConfig` - `@EnableWebSecurity` 
```java
//AuthenticationConfig - SecurityFilterChain
.authorizeHttpRequests(authorize -> authorize
        .requestMatchers("/api/**").permitAll()
        .requestMatchers("/api/v1/users/join", "/api/v1/users/login").permitAll() 
        .requestMatchers(HttpMethod.POST, "api/**").authenticated()) 
```
* 회원가입과 로그인은 누구나 권한 없이 언제나 접근할 수 있지만  
* 리뷰 쓰기 및 다른 모든 요청에 대해서는 권한 필요  

#### 1.2. JwtFilter 인증 계층 추가하기 
```java
//AuthenticationConfig - SecurityFilterChain
.addFilterBefore(new JwtFilter(userService, secretKey), 
        UsernamePasswordAuthenticationFilter.class)
```
* `addFilterBefore()`
  * JWT 인증 필터 `JwtFilter`를 `UsernamePasswordAuthenticationFilter` 이전에 추가하는 역할
  * 토큰이 있는지 매번 항상 확인해야 한다 
  ```java
  public HttpSecurity addFilterBefore(
      @NotNull jakarta.servlet.Filter filter,
      Class<? extends jakarta.servlet.Filter> beforeFilter)
  ```

#### 1.3. 모든 요청에 대해 권한 부여하기
> `public class JwtFilter extends OncePerRequestFilter { ... }`

```java
private final UserService userService;
private final String secretKey;
```
* Token 넣고 호출했을 때 인증하는 계층 필요  
* 받은 토큰을 풀어주어야하기 때문에 secretKey 필요

```java
@Override
protected void doFilterInternal(
        HttpServletRequest request, 
        HttpServletResponse response, 
        FilterChain filterChain) throws ServletException, IOException { ... }
```
* `Filter` 인터페이스를 구현하는 클래스에서 오버라이드할 메소드 중 하나
* HTTP 요청을 필터링하고, 필터가 적용된 요청을 처리하는 역할


```java
authenticationToken.setDetails(
        new WebAuthenticationDetailsSource().buildDetails(request));
```
*  사용자가 로그인할 때, 사용자의 IP 주소 및 사용자 에이전트 정보와 같은 웹 관련 정보 인증 토큰에 추가
* `UsernamePasswordAuthenticationToken.setDetails()`
  * `UsernamePasswordAuthenticationToken` 객체에 추가 정보 설정
  * 사용자 인증과 관련된 추가 정보를 포함하고, 나중에 이 정보를 검색하거나 활용할 수 있다 
* `WebAuthenticationDetailsSource()`
  * 웹 애플리케이션에서의 인증 요청과 관련된 세부 정보를 생성하는 클래스
  * 보통 이 세부 정보에는 IP 주소, 사용자 에이전트 정보 등이 포함된다
* `buildDetails(httpServletRequest)`
  * `buildDetails()` 메소드는 주어진 `HttpServletRequest` 객체로부터 웹 인증 세부 정보를 생성한다
  * `HttpServletRequest` 객체는 웹 요청과 관련된 정보를 포함하고,  
    이를 기반으로 IP 주소 및 사용자 에이전트 정보를 추출한다  
  
```java
SecurityContextHolder.getContext().setAuthentication(authenticationToken);
```
* 현재 사용자의 인증 정보를 `authenticationToken`으로 변경 
* `SecurityContextHolder.getContext()`
  * 현재 사용자 및 인증 정보를 관리하는 `SecurityContextHolder` 객체에서   
  * 현재 사용자와 관련된 정보가 저장되는 보안 컨텍스트 가져오기 
* `.setAuthentication(UsernamePasswordAuthenticationToken)`
  * 현재 사용자의 인증 정보 `UsernamePasswordAuthenticationToken`으로 설정

```java
filterChain.doFilter(request, response);
```
* `doFilter()`
  ```java
  public abstract void doFilter(
      jakarta.servlet.ServletRequest request,
      jakarta.servlet.ServletResponse response)
  ```
  * `Filter` 인터페이스를 구현한 필터에서 정의된 메소드
  * 필터가 요청(request) 및 응답(response)을 처리하는 메소드
  * 필터는 이 메소드를 통해 요청과 응답을 가로채고 수정할 수 있다  
    ex. 요청을 가로채 권한 확인하기  
  * 현재 필터에서 요청 및 응답을 처리하고,  
    이후에 실행될 다음 필터를 호출하기 위해 `FilterChain`의 `doFilter()`를 호출하는데,     
    이 때, 다음 필터로 요청 및 응답 계속 전달  

### 2. `TOKEN` 여부 확인
>   * TOKEN 있으면 권한 부여
>   * TOKEN이 없으면 권한 부여하지 않기

#### TOKEN이 없으면 권한 부여하지 않기 
```java
//JwtFilter - doFilterInternal 

//Header에서 TOKEN 꺼내기
final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
log.info("authorization : {}", authorization); //Slf4j 

//TOKEN 없으면 권한 부여 전 리턴
if (authorization == null || !authorization.startsWith("Bearer ")) {
    log.error("잘못된 authorization 또는 없음");
    filterChain.doFilter(request, response);
    return;
}

//TOKEN 꺼내기 - "Bearer " 제거
        String token = authorization.split(" ")[1];
        log.info("TOKEN - {}", token);
```

#### 포스트맨 
![토큰 여부 확인](https://github.com/yoonsseo/spring-security/assets/90557277/ee2417f8-8d15-4438-98e9-0bfed4a28aa8)   
* 토큰이 없으면 작동하지 않음!  

|![토큰 여부](https://github.com/yoonsseo/spring-security/assets/90557277/ffdc1741-87ba-45b4-a427-1a26716e3df9)| 근데 <br> 아무 `TOKEN`을 넣어도 <br> 작동하는 문제! |
|---|---------------------------------------|

### 3. `TOKEN` 유효성 검증
> - TOKEN의 유효시간이 지났는지 확인하기

#### TOKEN 유효시간 만료되었는지 확인
```java
//JwtUtil 
public static boolean isExpired(String token, String secretKey) {
    String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKey.getBytes());
    SecretKey key = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());

    Date expiration = Jwts.parserBuilder()
    .setSigningKey(key)
    .build()
    .parseClaimsJws(token)
    .getBody()
    .getExpiration();
    
    boolean isExpired = expiration.before(new Date());

    return isExpired;
    }
```
```java
//TOKEN 유효시간 검증
if (JwtUtil.isExpired(token, secretKey)) {
    log.error("TOKEN 만료");
    filterChain.doFilter(request, response);
    return;
}
```
#### 포스트맨
![토큰 만료](https://github.com/yoonsseo/spring-security/assets/90557277/c72bb59b-7418-4be7-9370-1052cbe69dfd)  
* `TOKEN` 유효 시간 이내에 리뷰 쓰기를 하면 `TOKEN`과 관련된 로그가 잘 나왔지만


* `TOKEN` 유효 시간 이후에 리뷰 쓰기를 하면 `TOKEN` 만료로 인한 `ExpiredJwtException`이 발생한다 

### 4. `TOKEN`에서 userName(ID) 꺼내서 Controller에서 사용하기  
#### 4.1. userName(ID) 추출
```java
//TOKEN에서 userName 꺼내기
String userName = JwtUtil.getUsername(token, secretKey);
log.info("ID(userName) : {}", userName);

//권한 부여
UsernamePasswordAuthenticationToken authenticationToken =
        new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority("USER")));
```
* `TOKEN`에서 `userName(ID)`의 `Claim` 추출하는 메소드 `JwtUtil.getUsername()` 생성


* 그리고 추출한 `userName(ID)`을 `UsernamePasswordAuthenticationToken`에 넣어주면 `Controller`에서 `userName(ID)`을 사용할 수 있다 

#### 4.2. Controller에서 사용하기
```java
import org.springframework.security.core.Authentication;
...
@PostMapping
public ResponseEntity<String> writeReview(Authentication authentication) {
    return ResponseEntity.ok().body(authentication.getName() + " 리뷰 등록 완료");
}
```

#### 포스트맨
|![로그](https://github.com/yoonsseo/spring-security/assets/90557277/2f6ee378-7148-4249-ab40-03151779ade4)|![리뷰컨트롤러](https://github.com/yoonsseo/spring-security/assets/90557277/2da4d560-1a7a-4816-95d8-d28bf25e8bc9)|
|---|---|
* 로그도 잘 나오고 포스트맨에서도 결과가 잘 반영된 것을 확인할 수 있다 