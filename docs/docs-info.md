While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

    - Accounts — an AWS account reachable through the AWS Account Federation application in Okta. Its entitlements are the SAML roles available in that account.
    - Groups — Okta groups that carry AWS role access. The group resource type is registered so that group membership can be granted and revoked; this connector does not sync group membership itself.

2. Can the connector provision any resources? If so, which ones?

    Yes. It grants and revokes a user's SAML role on an AWS account, and grants and revokes Okta group membership. It does not create or delete accounts.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

    - **Okta domain**: the URL for the Okta organization, for example `acmeco.okta.com`.
    - **API token**: an Okta API token for the service account.
    - **AWS Okta App ID**: the Okta application id of the AWS Account Federation app to govern.

2. For each item in the list above:

   * How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.

     * **Okta domain**: the hostname the Okta admin console is served from.
     * **API token**: Okta Admin Console → **Security** → **API** → **Tokens** → **Create token**. The value is shown once. [Okta API token documentation](https://developer.okta.com/docs/guides/create-an-api-token/main/)
     * **AWS Okta App ID**: open the AWS Account Federation app in the Okta Admin Console; the id is the last path segment of the URL.

   * Does the credential need any specific scopes or permissions? If so, list them here.

     * **API token**: the token inherits the permissions of the admin who created it. Reading requires the ability to read applications, application assignments and groups. Provisioning group membership additionally requires Group Admin.

    * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

     * **Sync (read-only)**: a custom read-only admin role, or Read Only Administrator, is sufficient.
     * **Provisioning (read-write)**: Super Administrator, or the combination Read Only + Application Administrator + Group Administrator. Group membership provisioning fails without Group Admin.

     * What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)

     * **API token**: the creating user must be an Okta administrator with access to the admin console. The token carries that admin's permissions.

## Additional setup notes

1. This connector requires a separate Okta connector for the same Okta organization. Group membership is read from that connector, and the AWS role access a user holds through a group is resolved against it. Without the paired connector, group-based access does not resolve.

2. After a group membership changes, both connectors must sync before the change is reflected: the Okta connector first, because it is the source of the membership, then this connector, which re-runs the expansion.

3. The connector's behaviour depends on the AWS Account Federation app's own settings in Okta, not only on connector configuration. `useGroupMapping`, `joinAllRoles` and `identityProviderArn` are read from the application and determine which accounts and roles are discovered.

4. Converting a group-based application assignment into a direct one during provisioning is refused unless `--aws-allow-group-to-direct-assignment-conversion-for-provisioning` is set and the application has `joinAllRoles` or SAML role union enabled.
