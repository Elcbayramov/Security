package mysecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    /*
    User {
        username, password, role (admin/user)
    } qeydiyyat, girish
    Book {
        name, author, List<Comments>
    } CRUD
    Comment {
        title, text, user
    } CRUD
    Admin rolu olan user qeydiyyatdan kece bilmez
    Qeydiyatdan kecende role user olmalidi
    Kitabi Create, Update, Delete ancaq admin rolu olan
    user
    Comment-i her bir tokeni olan user yaza bilir

     */


    public static void main(String[] args) {
        SpringApplication.run(Application.class);
    }

}

