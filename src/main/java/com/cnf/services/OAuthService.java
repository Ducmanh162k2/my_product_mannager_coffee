//package com.cnf.services;

//import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
//import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
//import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.stereotype.Service;
//
//@Service
//public class OAuthService extends DefaultOAuth2UserService {
//    @Override
//    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws
//            OAuth2AuthenticationException {
//        return super.loadUser(userRequest);
//    }
//}

package com.cnf.services;

import com.cnf.entity.User;
import com.cnf.repository.IUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class OAuthService extends DefaultOAuth2UserService {

    @Autowired
    private IUserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // Gọi phương thức loadUser của lớp cha để lấy thông tin OAuth2User từ Google
        OAuth2User oAuth2User = super.loadUser(userRequest);

        // Lấy email từ Google
        String email = oAuth2User.getAttribute("email");

        // Tìm người dùng trong cơ sở dữ liệu dựa trên email
        User user = userRepository.findEmail(email);

        // Kiểm tra nếu tài khoản của người dùng không hoạt động (active = false)
        if (user != null && !user.getActive()) {
            throw new OAuth2AuthenticationException("OAuth2AuthenticationException");
        }

        // Trả về đối tượng OAuth2User
        return oAuth2User;
    }
}

