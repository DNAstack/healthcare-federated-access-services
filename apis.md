# Endpoints

This file documents the endpoints of IC and DAM.

## IC

### Main Endpoints

The following are the main IC endpoints.

- "/identity/v1alpha/{realm}/login/{name}": Redirected here from login page and selecting an IdP.
- "/identity/v1alpha/{realm}/loggedin/{name}": Redirected here from an IdP.
- "/identity/v1alpha/{realm}/inforelease": Redirected here from claim release consent page.
- "/identity/login": Redirected to here from Hydra login.
- "/identity/consent": Redirected to here from Hydra consent.
- "/identity/loggedin": Redirected to here from Identity Broker.

### Administration Endpoints

The following are administration endpoints for managing DAM.
They require "admin" permission.

- "/identity": metadata about the service, like versions of various services.

### Configuration Admin Endpoints

The following are used for managing IC's configuration.
They require "admin" permission.

- "/identity/v1alpha/{realm}/config" and sub-resources: manageing configuration.
- "/identity/v1alpha/{realm}/config/reset": resets the config to its initial version read from configuration file.
- "/identity/v1alpha/{realm}/config/history": history of configuration changes.

### Users, Tokens, and Consents Management Endpoints

The following implement a subset of SCIM V2 API.

- "/identity/scim/v2/{realm}/Users": user management, based on SCIM V2.
- "/identity/scim/v2/{realm}/Me": based on SCIM V2.
See "proto/scim/v2/users.proto" for details.

- "/tokens": tokens management.
See "proto/tokens/v1/consents.proto" for details.

"/consents": consent management.
See "proto/tokens/v1/tokens.proto"

### Configuration Non-Admin Endpoints

The following provide read-only access to non-admins for various parts of
IC configuration. They filter out sensitive parts of the configuration.

- "/identity/v1alpha/{realm}/identityProviders"
- "/identity/v1alpha/{realm}/clients/{name}"
- "/identity/v1alpha/{realm}/passportTranslators"

### Static Page Assets

- "/identity/static"

## DAM

### Main Endpoints

The following are the main DAM endpoints. Users can retrive access tokens for
resources they want using the following OIDC and DAM token checkout endpoints.

- "/dam/login": Redirected to here from Hydra login.
- "/dam/consent": Redirected to here from Hydra consent.
- "/dam/oidc/loggedin": Redirected to here from Identity Broker.
- "/dam/checkout": returns the batch of access tokens for the requested resources.

NOTE: "/dam/oidc/loggedin" will be renamedto "/dam/oidc/accept"

### Administration Endpoints

The following are administration endpoints for managing DAM.
They require "admin" permission.

- "/dam": metadata about the service, like versions of various services.
- "/dam/v1alpha/{realm}/processes": the list of background processes.
- "/dam/v1alpha/{realm}/processes/{name}": the state of a background process.

### Configuration Admin Endpoints

The following are used for managing DAM's configuration.
They require "admin" permission.

- "/dam/v1alpha/{realm}/config" and sub-resources: manageing configuration.
- "/dam/v1alpha/{realm}/config/reset": resets the config to its initial version read from configuration file.
- "/dam/v1alpha/{realm}/config/history": history of configuration changes.
- "/dam/v1alpha/{realm}/tests": performs a set of tests for validity of the current configuration.

### Configuration Non-Admin Endpoints

The following provide read-only access to non-admins for various parts of
DAM configuration. They filter out sensitive parts of the configuration.

- "/dam/v1alpha/{realm}/client/{name}"
- "/dam/v1alpha/{realm}/resources"
- "/dam/v1alpha/{realm}/resources/{name}"
- "/dam/v1alpha/{realm}/flatViews"
- "/dam/v1alpha/{realm}/resources/{name}/views"
- "/dam/v1alpha/{realm}/resources/{name}/views/{view}"
- "/dam/v1alpha/{realm}/resources/{name}/views/{view}/roles"
- "/dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}"
- "/dam/v1alpha/{realm}/targetAdapters"
- "/dam/v1alpha/{realm}/passportTranslators"
- "/dam/v1alpha/{realm}/damRoleCategories"
- "/dam/v1alpha/{realm}/testPersonas"
