This project shows what you can do with the minimum configuration to
set up an Authorization Server with a JWT token and a custom flow/grant type

For the Authorization Server you need to `@EnableAuthorizationServer`
and also configure at least one client registration
(`OAuth2ClientDetails`). You can see this is the bulk of
`Application.java`. 

An `AuthenticationManager` (named `authenticationManagerBean`) is created by 
the WebSecurityConfig class (it has a single user, named "user", with password 
"password" and a BksAuthenticationTokenProvider that always authenticates 
a token correctly).

The `BksTokenGranter` is responsible for retrieving the bks token and calling 
the authenticationManager to try to authenticate the request.

Usage examples:
User/Pass authentication in a password flow/grant type
```
curl -X POST -d 'grant_type=password&client_id=my-client-with-secret&client_secret=secret&username=user&password=password' 'http://localhost:8080/oauth/token'
```


Bks Token authentication in a bks_token flow/grant type
```
curl -X POST -d 'grant_type=bks_token&client_id=my-client-with-secret&client_secret=secret' 'http://localhost:8080/oauth/token?token=1234'
```