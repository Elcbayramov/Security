package mysecurity.security.userdetails.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import mysecurity.repository.UserRepository;
import mysecurity.security.userdetails.JwtUser;

@Service
public class JwtUserDetailsService implements UserDetailsService {

    UserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findByUsername(username)
                .map(JwtUser::new)
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

    @Autowired
    public void setAppUserRepository(UserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }
}
