# earthware-nancy-authentication

Extensions to the standard forms authentication provider for Nancy.

Extends the standard Nancy.Authentication.Forms library with sliding session expiry and randomly generated auth session ids.

## Changes

### 1.0.18 Nuget Release
Added a config option boolen of _NoExpiry_

    var formsAuthConfig = new FormsAuthenticationConfiguration
    {                
      NoExpiry = true,
      ... other properies ...
    };

This stops an expiry time being applied to the forms auth cookie, which makes it a session cookie. This means it will expire on browser close. If you still require a timeout as well you must implement that on the server API.

### 1.0.17 Nuget Release and before

No notes. Sorry.