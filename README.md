# Activité 4 : Sécurité des systèmes distribuées

## Première partie : configuration de KeyCloak
Dans le cadre de ce travail pratique, nous explorerons les mécanismes de sécurité offerts par Spring Security, conjugués à l'utilisation de Keycloak, un gestionnaire d'identité open source, pour renforcer la sécurité d'une application développée avec le framework Spring.
 
 ![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/e21e247c-acde-4613-a1cf-5678d56b73f4)

### Créer un nouveau realm 
![Capture](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/bf3e09aa-018d-483f-9f4b-940011fae97d)

### Créer un client 
![Capture2](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/284fc82c-4dad-45a1-ab1b-bf14a8447d65)

### Créer un utilisateur
![Capture3](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/2b9593a0-7998-4368-8f68-e7eaac5822f9)

### Créer un autre utilisateur
![Capture4](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/344869d0-831a-4bd0-bec6-bae2451c46ef)

### Créer les roles 'USER' et 'ADMIN'
![Capture5](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/4cffb46f-0a7d-46ff-9ad0-90d507f1c3e3)

### Affecter le role 'USER' au 'user'
![Capture6](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/6b439f81-ef92-4fb9-9b79-cdbdd43b0ea3)

### Affecter les roles 'USER' et 'ADMIN au 'kaoutar'
![Capture7](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/2071519b-8bb5-4c17-a84a-1556709b3669)

### POSTMAN
dans cette partie on va effectuer un certain nombre de tests sur postman
- Premier test
![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/137bea0d-e921-4419-a3da-bcff9ebeff6f)

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/5584a780-b335-4249-9f35-250797b9486c)

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/fac5ee03-a328-486d-9af8-1336b35ef50f)

- deuxième test
Cette fois ci on va effectuer le test à partir du secret client généré

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/d63874b0-2134-49a4-aada-c2cb00f0b63a)

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/f54b70dd-6f42-4994-9875-c481dc1764d2)

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/a4576cdb-7e21-4217-9cab-261d02db2496)


## Deuxième partie : Sécuriser une application

Tout d'abord on va sécuriser le Back-End du microservice E-Bank
1. Commmencant par ajouter les dépendances suivants:
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
2. Ajouter ces lignes de configuration dans 'application.properties'

```bash
keycloak.realm=wallet-realm 
keycloak.resource=wallet-client
keycloak.bearer-only=true 
keycloak.auth-server-url=http://Localhost:8080
keycloak.ssl-required=none
```
3. Créer le package security avec les deux classses 'KeycloakAdapterConfig' et 'SecurityConfig'
   - SecurityConfig
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
- KeycloakAdapterConfig
```bash
      @Configuration
public class KeycloakAdapterConfig {
    @Bean
    KeycloakSpringBootConfigResolver springBootConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }
}
```
4. Controller
```bash
@RestController
@CrossOrigin("*")
public class EBankRestController {
    @Autowired
    private EBankServiceImpl eBankService;
    @PostMapping("/currencyTransfer")
    @PreAuthorize("hasAuthority('ADMIN')")
    public CurrencyTransferResponse currencyTransfer(@RequestBody NewWalletTransferRequest request){
        return this.eBankService.newWalletTransaction(request);
    }
    @GetMapping("/currencyDeposits")
    @PreAuthorize("hasAuthority('USER')")
    public List<CurrencyDeposit> currencyDepositList(){
        return eBankService.currencyDeposits();
    }
}
```
#### Effectuer un test
![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/2c2dac9f-2438-43e2-933a-e70cfd61d5b8)

![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/efc311c1-df7a-408b-b4b4-70b745ea9bdb)

#### Partie FrontEnd
```bash
npm install keycloak-angular keycloak-js --force
```
- modifier dans app.module.ts
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
- créer un fichier security.guard.ts
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
- Aller vers navbar
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
- Spécifier les roles dans app.routing.module.ts
```bash
const routes: Routes = [
  {
    path : "currencies", component : CurrenciesComponent
  },
  {
    path : "continents", component : ContinentsComponent
  },
  {
    path : "wallets", component : WalletsComponent
  },
  {
    path : "transactions/:walletId", component : WalletTransactionsComponent, canActivate : [AuthGuard],
    data : {roles: ['USER','ADMIN']}
  },
  {
    path : "currencyDeposit", component : CurrencyDepositComponent,
  }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```
- Résultat de sécurisation
  ![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/06d774a3-8136-432f-b7ce-202b7eac15bf)
  ![image](https://github.com/Userkaoutar/Activite4-Securite-des-systemes-distribues/assets/101696114/c2fdadc0-39f7-43f4-898b-1741e87e895a)




