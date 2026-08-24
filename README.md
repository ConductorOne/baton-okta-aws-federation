![Baton Logo](./docs/images/baton-logo.png)

# `baton-okta-aws-federation` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-okta-aws-federation.svg)](https://pkg.go.dev/github.com/conductorone/baton-okta-aws-federation) ![ci](https://github.com/conductorone/baton-okta-aws-federation/actions/workflows/ci.yaml/badge.svg) ![verify](https://github.com/conductorone/baton-okta-aws-federation/actions/workflows/verify.yaml/badge.svg)

`baton-okta-aws-federation` is a connector for Okta built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It governs a single AWS Account Federation SAML application inside an Okta organization: it syncs the AWS accounts reachable through that application, the SAML roles available in each, and who holds them.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-okta-aws-federation

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com BATON_AWS_OKTA_APP_ID=awsAppID baton-okta-aws-federation
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_API_TOKEN=oktaAPIToken -e BATON_DOMAIN=domain-1234.okta.com -e BATON_AWS_OKTA_APP_ID=awsAppID ghcr.io/conductorone/baton-okta-aws-federation:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-okta-aws-federation/cmd/baton-okta-aws-federation@main

BATON_API_TOKEN=oktaAPIToken BATON_DOMAIN=domain-1234.okta.com BATON_AWS_OKTA_APP_ID=awsAppID baton-okta-aws-federation
baton resources
```

# Data Model

`baton-okta-aws-federation` syncs two resource types from the AWS Account Federation
application it is pointed at:

- **Accounts** — an AWS account reachable through the application. Its entitlements are the
  SAML roles available in that account.
- **Groups** — Okta groups that carry AWS role access. This connector does not sync groups as
  first-class resources; the group resource type exists so that group membership can be
  granted and revoked. See "Group membership and the paired Okta connector" below.

Grants on an account's role entitlements are emitted to two kinds of principal: directly to
the Okta users assigned to the application, and to the Okta groups assigned to it.

## Group membership and the paired Okta connector

This connector reads AWS role access; it does not read Okta group membership. Grants it emits
to a group principal carry an annotation pointing at that group's `member` entitlement, and
C1's grant expansion resolves those against a **separate Okta connector** synced from the same
Okta organization. Two consequences worth knowing before you deploy it:

- An Okta connector for the same organization must exist alongside this one. Without it, the
  group membership behind AWS role access does not resolve.
- After a group membership changes, both connectors need to sync before the change is
  reflected — the Okta connector first, because it is the source of the membership, then this
  one, which re-runs the expansion.

Granting or revoking a group's `member` entitlement is dispatched to this connector, which
calls Okta's group membership API directly.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-okta-aws-federation` Command Line Usage

```
baton-okta-aws-federation

Usage:
  baton-okta-aws-federation [flags]
  baton-okta-aws-federation [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  config             Get the connector config schema
  help               Help about any command

Flags:
      --api-token string                                                   required: The API token for the service account ($BATON_API_TOKEN)
      --aws-allow-group-to-direct-assignment-conversion-for-provisioning   Whether to allow group to direct assignment conversion when provisioning ($BATON_AWS_ALLOW_GROUP_TO_DIRECT_ASSIGNMENT_CONVERSION_FOR_PROVISIONING)
      --aws-okta-app-id string                                             required: The Okta app id for the AWS application ($BATON_AWS_OKTA_APP_ID)
      --cache                                                              Enable response cache ($BATON_CACHE) (default true)
      --cache-tti int                                                      Response cache cleanup interval in seconds ($BATON_CACHE_TTI) (default 60)
      --cache-ttl int                                                      Response cache time to live in seconds ($BATON_CACHE_TTL) (default 300)
      --client-id string                                                   The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string                                               The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --domain string                                                      required: The URL for the Okta organization ($BATON_DOMAIN)
      --external-resource-c1z string                                       The path to the c1z file to sync external baton resources with ($BATON_EXTERNAL_RESOURCE_C1Z)
      --external-resource-entitlement-id-filter string                     The entitlement that external users, groups must have access to sync external baton resources ($BATON_EXTERNAL_RESOURCE_ENTITLEMENT_ID_FILTER)
  -f, --file string                                                        The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                                                               help for baton-okta-aws-federation
      --log-format string                                                  The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                                   The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --otel-collector-endpoint string                                     The endpoint of the OpenTelemetry collector to send observability data to (used for both tracing and logging if specific endpoints are not provided) ($BATON_OTEL_COLLECTOR_ENDPOINT)
  -p, --provisioning                                                       This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync                                                     This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --sync-resources strings                                             The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --ticketing                                                          This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                                                            version for baton-okta-aws-federation

Use "baton-okta-aws-federation [command] --help" for more information about a command.
```
