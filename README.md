# TP-4Securite-des-Systemes-Distribues
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/16d0efc2-5540-4bcf-b456-880f19e78478)
## Partie 1 : Configuration de l'environnment
 ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/a5c281c6-4f5c-4a59-aa9f-7fbbc9d233ba)
### Création d'un nouveau realm "wallet-realm"
 ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/4be7729e-df07-4371-bcbb-166ee6803e2a)
### Création d'un nouveau client "wallet-client"
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/6ca607ec-d10a-4afd-b437-ce6af705c47a)
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/853857e1-0462-47f5-af8e-0ec1c39e2c9e)
### Création de l'utilisateur "user1"
 ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/887b2ec6-358e-49e1-b2ec-464ea9f128f6)
### Création de l'utilisateur "taghla2"
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/ecdea7ec-6d1c-4b07-8498-ae9a849efd24)
### Affecter au "user1" le role "USER"
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/327fd2cc-9974-4121-892c-404808d313e8)
### Affecter au "taghla2" leS roles "USER" et "ADMIN"
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/3bb31cf6-9146-4045-8af2-4596a725bfde)
### Test sur Postman
- Test 1
   ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/f2ad0452-d036-402c-9431-b9fcaabf9edf)
  ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/ad139ad1-929c-4074-9cbd-df1a80329f33)
- Test 2
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/1d1f17c6-c210-4f29-8b2f-87a1fe15886b)
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/56c71cb4-33df-441d-aad8-5440dfaeb2c5)
 - Test 3
On active l'authentification pour le client puis on effectue un test sur postman avec le secret généré
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/bf37c8f7-f661-402a-9261-2eb4993d1bbd)
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/45f31b97-5c66-4bce-b651-932bb568cbd6)
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/4e7ba5f6-de5c-4585-9658-2137a1d3d068)
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/14f4d831-a531-4242-ab24-4678271d28bc)

## Partie 2: Sécurisation
### E-Bank
    1- Configuration "application.properties"
 ```bash
 keycloak.realm=wallet-realm 
keycloak.resource=wallet-client
keycloak.bearer-only=true 
keycloak.auth-server-url=http://Localhost:8080
keycloak.ssl-required=none
 ```
  2. Ajouter des dépendances:
```bash
<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-security</artifactId>
		</dependency>
		<dependency>
			<groupId>org.keycloak</groupId>
			<artifactId>keycloak-spring-boot-starter</artifactId>
			<version>19.0.2</version>
		</dependency>
 ```
 3. Désactiver le SSL
    ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/45cbebe6-2520-4600-8beb-aa886695720a)

 4. Créer le package security avec les deux classses 'KeycloakAdapterConfig' et 'SecurityConfig'
```bash
    @Configuration
public class KeycloakAdapterConfig {
    @Bean
    KeycloakSpringBootConfigResolver springBootConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
}
```
```bash
@KeycloakConfiguration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Override
    protected void configure(org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }

    @Override
    protected void configure(org.springframework.security.config.annotation.web.builders.HttpSecurity http) throws Exception {
        super.configure(http);
        http.csrf().disable();
        http.authorizeRequests().anyRequest().authenticated();
    }
}
```
 - Revenant vers POSTMAN pour avoir le token JWT
   ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/71081f74-92f2-4f42-938e-1fddeb2cb07d)
   ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/b270c63e-db7e-4327-9391-04dda66cdf2c)
   ![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/43965d7d-d0e2-4a19-b09e-7bf387b28276)

  ### Wallet-Service 
  De meme on va sécuriser le wallet service
  ### Front-End
   1. Les dépendances
```bash
npm install keycloak-angular keycloak-js --force
```bash
   2. security.guard.ts
```bash
import { Injectable } from '@angular/core';
import {
  ActivatedRouteSnapshot,
  Router,
  RouterStateSnapshot
} from '@angular/router';
import { KeycloakAuthGuard, KeycloakService } from 'keycloak-angular';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard extends KeycloakAuthGuard {
  constructor(
    protected override readonly router: Router,
    protected readonly keycloak: KeycloakService
  ) {
    super(router, keycloak);
  }

  public async isAccessAllowed(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ) {
    // Force the user to log in if currently unauthenticated.
    if (!this.authenticated) {
      await this.keycloak.login({
        redirectUri: window.location.origin
      });
    }

    // Get the roles required from the route.
    const requiredRoles = route.data['roles'];

    // Allow the user to proceed if no additional roles are required to access the route.
    if (!Array.isArray(requiredRoles) || requiredRoles.length === 0) {
      return true;
    }

    // Allow the user to proceed if all the required roles are present.
    return requiredRoles.every((role) => this.roles.includes(role));
  }
}
```
3. app.module.ts
 ```bash
export function KcFactory(KcService : KeycloakService){
  return ()=>{
    KcService.init({
      config :{
        realm :"wallet-realm",
        clientId :"wallet-client",
        url :"http://localhost:8080"
      },
      initOptions : {
        onLoad :"check-sso",
        checkLoginIframe: true
      }
    })
  }
}
```
```bash
providers: [
    {
      provide: APP_INITIALIZER, deps :[KeycloakService],useFactory: KcFactory,multi:true
    }
  ],
```
4. security.service.ts
  ```bash
import {Injectable} from "@angular/core";
import {KeycloakProfile} from "keycloak-js";
import {KeycloakEventType, KeycloakService} from "keycloak-angular";

@Injectable({providedIn : "root"})
export class SecurityService {
  public profile? : KeycloakProfile;
  constructor (public kcService: KeycloakService) {
    this.init();
  }
  init(){
    this.kcService.keycloakEvents$.subscribe({
      next: (e) => {
        if (e.type == KeycloakEventType.OnAuthSuccess) {
          this.kcService.loadUserProfile().then(profile=>{
            this.profile=profile;
          });
        }
      }
    });
  }
  public hasRoleIn(roles:string[]):boolean{
    let userRoles = this.kcService.getUserRoles();
    for(let role of roles){
      if (userRoles.includes(role)) return true;
    } return false;
  }
}
  ```
5. navbar.component.ts
```bash
   onLogout() {
    this.securityService.kcService.logout(
        window.location.origin
    )

}
async login(){
    this.securityService.kcService.login(
{redirectUri: window.location.origin}
    )
    }
```
et voila l'application devient sécurisé
![image](https://github.com/Taghla-Ladkhan/TP-4Securite-des-Systemes-Distribues/assets/101521160/25c9b83a-513a-4592-865d-414999482e49)




