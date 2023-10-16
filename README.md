# spring-security

## 회원가입 
> 1. `POST` `/api/v1/users/join` 만들기   
>    - RequestBody - userName, password
> 2. 회원가입 성공/실패 Controller Test
> 3. `UserService.join()` - 중복 체크해서 `ifPresent`면 `RuntimeException` 리턴
>    - `@RestControllerAdvice` 선언
>    - `@ExceptionHandler`로 `RuntimeException` 받기
>4. `CuntomException`으로 변경
>    - ErrorCode 선언
>    - 중복 check exception 수정

### 1. 간단한 `User`, `UserRepository`, `UserService`, `UserController`, `JoinRequestDto` 생성
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

### 3. `@RestControllerAdvice`를 통해 `@ExceptionHandler`로 특정 exception을 받아 처리할 수 있다

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

