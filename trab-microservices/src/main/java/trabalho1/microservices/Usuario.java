package trabalho1.microservices;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequestMapping("/usuario")
public class Usuario {

  @Autowired
  private UsuarioDAO dao;

  @PostMapping
  public ResponseEntity<String> createUser(@RequestBody UsuarioBean user) throws DupedIdException {

    if (dao.count() == 0) {
      System.out.println("Base de usuários vazia.");
      dao.save(user);
      return new ResponseEntity<String>(user.getUsername(), HttpStatus.CREATED);
    } else if (dao.findByUsername(user.getUsername()) != null) {
      System.out.println("Este nome de usuário já foi tomado!");
      return new ResponseEntity<String>("Este nome de usuário já está em uso", HttpStatus.NOT_ACCEPTABLE);
    }
    System.out.println("Criando novo usuário");
    user.setTotalFails(0);
    user.setTotalLogins(0);
    System.out.println(user);
    dao.save(user);
    return new ResponseEntity<String>(user.getUsername(), HttpStatus.CREATED);
  }

  @GetMapping()
  public ResponseEntity<Iterable<UsuarioBean>> allUsers() {
    System.out.println(dao.count());

    if (dao.count() > 0) {
      return new ResponseEntity<Iterable<UsuarioBean>>(dao.findAll(), HttpStatus.OK);
    } else {
      System.out.println("Não há registros de usuários.");
      return new ResponseEntity<Iterable<UsuarioBean>>(HttpStatus.NO_CONTENT);
    }
  }

  @PutMapping()
  public ResponseEntity<String> updateUser(@RequestBody UsuarioBean user) {
    if (user.getUsername() == null || user.getPassword() == null) {
      return new ResponseEntity<String>("Informações de login incompletas", HttpStatus.BAD_REQUEST);
    }

    UsuarioBean userExists = dao.findByUsername(user.getUsername());
    if (userExists == null) {
      System.out.println("Usuário não localizado");
      return new ResponseEntity<String>("Usuário não encontrado", HttpStatus.UNAUTHORIZED);
    }

    if (userExists.isBlocked()) {
      System.out.println("Acesso para este usuário foi bloqueado");
      return new ResponseEntity<String>("Acesso para este usuário foi bloqueado", HttpStatus.UNAUTHORIZED);
    }

    try {
      if (userExists.getTotalLogins() > 10) {
        System.out.println("Número máximo de logins excedido, altere sua senha");
        return new ResponseEntity<String>("Número máximo de logins excedido, altere sua senha", HttpStatus.UNAUTHORIZED);
      }
    } catch (Exception e) {
    }

    if (!userExists.getPassword().equals(user.getPassword())) {
      System.out.println("Senha inválida");

      try {
        userExists.setTotalFails(userExists.getTotalFails() + 1);
      } catch (Exception e) {
        userExists.setTotalFails(1);
      }

      if (userExists.getTotalFails() > 5) {
        userExists.setBlocked(true);
        System.out.println("Usuário agora está bloqueado");
      }

      dao.save(userExists);
      return new ResponseEntity<String>("Senha inválida", HttpStatus.UNAUTHORIZED);
    }

    try {
      userExists.setTotalLogins(userExists.getTotalLogins() + 1);
    } catch (Exception e) {
      userExists.setTotalLogins(1);
    }

    dao.save(userExists);
    return new ResponseEntity<String>("Usuário autenticado com sucesso", HttpStatus.OK);
  }

  @GetMapping("/bloqueados")
  public ResponseEntity<UsuarioBean[]> usuariosBloqueados() {
    UsuarioBean[] bloqueados = dao.findByBlockedTrue();

    System.out.println(bloqueados.length);

    if (bloqueados.length > 0) {
      return new ResponseEntity<UsuarioBean[]>(bloqueados, HttpStatus.OK);
    } else {
      System.out.println("Nenhum usuário bloqueado encontrado");
      return new ResponseEntity<UsuarioBean[]>(HttpStatus.NO_CONTENT);
    }
  }

  @PutMapping("/trocasenha")
  public ResponseEntity<String> trocaSenha(@RequestBody TrocaSenhaBean user) {
    UsuarioBean userExists = dao.findByUsername(user.getUsername());

    if (userExists == null) {
      System.out.println("Usuário não localizado");
      return new ResponseEntity<String>("Usuário não encontrado", HttpStatus.NOT_FOUND);
    }

    if (userExists.isBlocked()) {
      System.out.println("Usuário com acesso bloqueado");
      return new ResponseEntity<String>("Usuário com acesso bloqueado", HttpStatus.UNAUTHORIZED);
    }

    if (!userExists.getPassword().equals(user.getCurrentPassword())) {
      System.out.println("A senha atual não corresponde");
      return new ResponseEntity<String>("A senha atual não corresponde", HttpStatus.UNAUTHORIZED);
    }

    if (userExists.getPassword().equals(user.getNewPassword())) {
      System.out.println("Não há alteração na senha");
      return new ResponseEntity<String>("Nova senha não pode ser igual à atual", HttpStatus.BAD_REQUEST);
    }

    userExists.setPassword(user.getNewPassword());
    userExists.setTotalLogins(0);
    dao.save(userExists);
    return new ResponseEntity<String>("Senha atualizada com sucesso", HttpStatus.OK);
  }

@PostMapping("/desbloquear/{username}")
@PreAuthorize("hasRole('ADMIN')")
  public ResponseEntity<String> unblockUser(@PathVariable String username) {
    return username == null ? 
        ResponseEntity.badRequest().body("Necessário especificar um usuário") : 
        Optional.ofNullable(dao.findByUsername(username))
            .map(user -> !user.isBlocked() ? 
                ResponseEntity.badRequest().body("Usuário não está bloqueado") : 
                desbloquearUsuario(user))
            .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).body("Usuário não localizado"));
  }

  private ResponseEntity<String> desbloquearUsuario(UsuarioBean user) {
    user.setTotalFails(0);
    user.setBlocked(false);
    dao.save(user);
    return ResponseEntity.ok("Bloqueio removido com sucesso");
  }
}