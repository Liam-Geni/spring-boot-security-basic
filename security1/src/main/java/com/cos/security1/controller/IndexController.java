package com.cos.security1.controller;

import com.cos.security1.controller.request.UserRequest;
import com.cos.security1.entity.User;
import com.cos.security1.repository.UserRepository;
import org.jboss.jandex.Index;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller //view를 리턴하겠다.
public class IndexController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    public IndexController(UserRepository userRepository,
                           BCryptPasswordEncoder bCryptPasswordEncoder){
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @GetMapping({"","/"})
    public String index(){
        return "index";
    }
    @GetMapping("/user")
    public @ResponseBody String user(){
        return "user";
    }
    @GetMapping("/admin")
    public @ResponseBody String admin(){
        return "admin";
    }
    @GetMapping("/manager")
    public @ResponseBody String manager(){
        return "manager";
    }
    //login은 스프링 시큐리티가 낚아챔
    @GetMapping("/loginForm")
    public String loginForm(){
        return "loginForm";
    }
    @GetMapping("/joinForm")
    public String joinForm(){
        return "joinForm";
    }
    @PostMapping("/join")
    public String join(User user){
        user.setRole("USER");
        String rawPwd = user.getPassword();
        String encodePwd = bCryptPasswordEncoder.encode(rawPwd);
        user.setPassword(encodePwd);
        userRepository.save(user);  //회원가입 잘됨. 비밀번호 : 1234 = > 시큐리티로 로그인을 할 수 없음. 이유는 패스워드 암호화가 안되었기 때문에
        return "redirect:/loginForm";
    }

    //해당하는 한개의 주소에 한개의 ROLE을 입력하고 싶을때
    @Secured("ROLE_ADMIN")
    @GetMapping("/info")
    public @ResponseBody String info(){
        return "개인정보";
    }

    //해당하는 한개의 주소에 한개이상의 ROLE을 넣고 싶을때
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    public @ResponseBody String data(){
        return "데이터 정보";
    }
}
