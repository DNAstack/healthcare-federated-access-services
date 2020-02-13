# API Endpoints

This file documents the endpoints of IC and DAM.

Concepts used within the API endpoints include:

*  **API Version:** `v1alpha` is the current API version of these components,
   and is used as part of the resource path on most endpoints. Some standard
   OIDC endpoints, metadata endpoints, and other API integration endpoints do
   not include the API version.

*  **Realms:** `realm` is a form of namespace that allows data to be partitioned
   within a single deployment of the service.
   *  Realms can be used to experiment with different configurations. For
      example, an administrator could introduce "staging" and "prod" realms to
      test upcoming config changes.
   *  Realms can be used to separate different usage scenarios from each other.
      For example, two different departments within one organization can each
      have their own realm with different configurations.
   *  **Realms do not have any additional protection against use**, so all users
      and administrators of any one realm may have the ability to access other
      realms if they choose to.

*  **Experimental Features:** Some of the API is restricted to "experimental"
   usage, and is not appropriate for production workloads and may not meet
   security requirements in their current form. These are often newer features
   that are not yet ready for adoption.
   *  Setting an environment variable enables these experimental features. They
      are not enabled by default.
         ```
         export FEDERATED_ACCESS_ENABLE_EXPERIMENTAL=true
         ```
   *  Experimental features are expected to change more significantly and more
      frequently than non-experimental parts of the API.
   *  Experimental features are more likely to be removed in the future based
      on feedback and evolution of the features they represent.

## IC

### Main Endpoints

The following are the main IC endpoints:

*  "/identity/v1alpha/{realm}/login/{name}": Redirected here from login page and selecting an IdP.
*  "/identity/v1alpha/{realm}/loggedin/{name}": Redirected here from an IdP.
*  "/identity/v1alpha/{realm}/inforelease": Redirected here from claim release consent page.
*  "/identity/login": Redirected to here from Hydra login.
*  "/identity/consent": Redirected to here from Hydra consent.
*  "/identity/loggedin": Redirected to here from Identity Broker.

### Service Info Endpoints

The following are public endpoints for discovery and/or health check.

*  "/identity": metadata about the service, like versions of various services.

### Configuration Admin Endpoints

The following are used for managing IC's configuration.
They require "admin" permission.

*  "/identity/v1alpha/{realm}/config" and sub-resources: managing configuration.
*  "/identity/v1alpha/{realm}/config/reset": resets the configuration to its initial version read from configuration file.
*  "/identity/v1alpha/{realm}/config/history": history of configuration changes.

### Users, Tokens, and Consents Management Endpoints

The following implement a subset of [SCIM V2 API](https://tools.ietf.org/html/rfc7644#section-3.2).

*  "/identity/scim/v2/{realm}/Users": user management, based on the
   [SCIM V2 User Resource Schema](https://tools.ietf.org/html/rfc7643#section-4.1).
*  "/identity/scim/v2/{realm}/Me": based on the
   [SCIM V2 Me Authenticated Subject Alias](https://tools.ietf.org/html/rfc7644#section-3.11).

SCIM-like endpoints have the following user management limitations:

*  See "proto/scim/v2/users.proto" for details of the structure that is
   supported.
*  Account management updates require the `account_admin` scope on the access
   token.
*  A [limited subset of filters](#scim-filters) is available.
*  Only a limited number of object attributes (i.e. object fields) are available
   for PATCH. For example, `primary` for emails and `value` for photos.

#### Account Linking

You can link accounts using the following extension to SCIM V2:

1. Account 1: Login to the IC with the both the `account_admin` and `link`
   scopes.
2. Account 2: Login to the IC with another account with `account_admin` and
   `link` scopes.
3. Make a PATCH request to `/identity/scim/v2/{realm}/Me` while providing Account
   1 and Account 2 bearer tokens via the `Authorization` and
   `X-Link-Authorization` headers, and a body that contains a patch operation
   as follows:

       ```
       {
           "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
           "Operations":[
               { "op": "add", "path": "emails", "value": "X-Link-Authorization" }
           ]
       }
       ```

The following is a code sample of a PATCH request to link accounts given
variables (`serviceURL`, `clientId`, `clientSecret`, `token1` and `token2`):

```
let patch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`;
$.ajax({
    url: `${serviceURL}/identity/scim/v2/master/Me?client_id=${clientId}&client_secret=${clientSecret}`,
    type: "PATCH",
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    data: patch,
    processData: false,
    beforeSend: function(xhr){
        xhr.setRequestHeader('Authorization', `Bearer ${token1}`);
        xhr.setRequestHeader('X-Link-Authorization', `Bearer ${token2}`);
    },
    success: function(resp) {
        console.log("LINK ACCOUNT SUCCESS:\n\n" + JSON.stringify(resp, undefined, 2));
    },
    error: function(err, status, info) {
        console.log(JSON.stringify(err, undefined, 2) + `,\nstatus: "${status}", info: "${info}"`);
    }
});
```

#### SCIM Filters

**Note:** DAM and IC support only a subset of the SCIM V2 filter specification,
and only on supported user management endpoints where appropriate.

SCIM-like filters that are supported by DAM and IC are generally of the form:

```
<expr> = <attribute> <compare_op> "string" | <attribute> <compare_op> boolean
```

*  **`attribute`:** an attribute path such as `active` or `name.formatted`
*  **`compare_op`:** a comparison operator such as `eq` (equals), `co` (contains),
   etc. See [SCIM V2 Filtering](https://tools.ietf.org/html/rfc7644#section-3.4.2.2)
   documentation for the full list of filter operators.
*  `string` or `boolean` is based on the `attribute` type.

Multiple clauses within filter expressions are limited to the following:

```
<expr> or <expr> or ...

<expr> and <expr> and ...

(<expr> or <expr> or ...) and (<expr> or <expr> or ...) and <expr>
```

That is, parentheses may be used to collect `or` clauses only, with `and` being
used between bracketed clauses to support expressions that are in
[Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form).
Brackets are not needed on sub-expressions between `and` clauses if each
such sub-expression contains no `or` subclauses. See example above ending in
`... and <expr>` without parentheses around `<expr>`.

When using filters to patch a specific object in a list, use `$ref` as the
filter for that object. For example:

```
{
    "op": "replace",
    "path": "emails[$ref eq \"email/persona/non-admin\"].primary",
    "value":"true"
}
```

#### Tokens and Consents

The following token and consents are used:

*  "/tokens": tokens management. For more information, see
   "proto/tokens/v1/consents.proto".
*  "/consents": consent management. For more information, see
   "proto/tokens/v1/tokens.proto".

### Configuration Non-Admin Endpoints

The following provide read-only access to non-admins for various parts of
IC configuration. They filter out sensitive parts of the configuration.

*  "/identity/v1alpha/{realm}/identityProviders"
*  "/identity/v1alpha/{realm}/clients/{name}"
*  "/identity/v1alpha/{realm}/passportTranslators"

### Static Page Assets

The following static page assets are used:

*  "/identity/static"

## DAM

### Main Endpoints

The following are the main DAM endpoints. Users can retrieve access tokens for
resources they want using the following OIDC and DAM token checkout endpoints.

*  "/dam/login": Redirected to here from Hydra login.
*  "/dam/consent": Redirected to here from Hydra consent.
*  "/dam/oidc/loggedin": Redirected to here from Identity Broker.
*  "/dam/checkout": returns the batch of access tokens for the requested
   resources.

**NOTE:** "/dam/oidc/loggedin" will be renamed to "/dam/oidc/accept"

### Service Info Endpoints

The following are public endpoints for discovery and/or health check.

*  "/dam": metadata about the service, like versions of various services.

### Administration Endpoints

The following are administration endpoints for managing DAM.
They require "admin" permission.

*  "/dam/v1alpha/{realm}/processes": the list of background processes.
*  "/dam/v1alpha/{realm}/processes/{name}": the state of a background process.

### Configuration Admin Endpoints

The following are used for managing DAM's configuration.
They require "admin" permission.

*  "/dam/v1alpha/{realm}": supports GET and DELETE of a realm.
*  "/dam/v1alpha/{realm}/config" and sub-resources: managing configuration.
*  "/dam/v1alpha/{realm}/config/reset": resets the config to its initial version read from configuration file.
*  "/dam/v1alpha/{realm}/config/history": history of configuration changes.
*  /dam/v1alpha/{realm}/tests": performs a set of tests for validity of the current configuration.

### Configuration Non-Admin Endpoints

The following provide read-only access to non-admins for various parts of
DAM configuration. They filter out sensitive parts of the configuration.
They require valid "client_id" and "client_secret" parameters on the request.

*  /dam/v1alpha/{realm}/client/{name}
*  /dam/v1alpha/{realm}/resources
*  /dam/v1alpha/{realm}/resources/{name}
*  /dam/v1alpha/{realm}/flatViews
*  /dam/v1alpha/{realm}/resources/{name}/views
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}
*  /dam/v1alpha/{realm}/targetAdapters
*  /dam/v1alpha/{realm}/passportTranslators
*  /dam/v1alpha/{realm}/damRoleCategories
*  /dam/v1alpha/{realm}/testPersonas
