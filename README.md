# OAuthSeeker

**OAuthSeeker** is an red team tool for performing phishing attacks using malicious OAuth applications to compromise user identities within Microsoft Azure and Office365. 

## 🚀 Key Features

OAuthSeeker provides the following key features:

- **Azure App OAuth Phishing:** Perform OAuth phishing attacks targeting Microsoft Azure and Office365 users to gain access to Microsoft Graph API and Microsoft Azure resources.
- **Admin Control Panel**: Provides an administrative control panel which is accessible by default on the localhost interface and includes authentication by default.
- **Token Refresher**: Automated token refresh operations to keep captured refresh tokens associated with captured credentials alive.
- **Custom Skins**: Ability to reskin user-facing frontend components to fit various cover identities used during phishing attacks.
- **LetsEncrypt Integration**: Configure HTTPS support with LetsEncrypt for secure connections along with support for user-provided and self-signed certificates.
- **Easy Deployment:** Deploy easily using a single Go binary containing all the built-in functionality with sane default for most operations.

## ⚙️ Quick Start Guide

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/oauthseeker.git
   cd oauthseeker
   ```
2. **Building the Tool**:
   ```bash
   go build -o oauthseeker
   ```
3. **Obtain an Access Token for App Registration:**
   ```bash
   export JWT=$(az account get-access-token --resource https://graph.microsoft.com | jq -r .accessToken)
   ```
5. **Register and Install a New Systemd Application in OAuthSeeker:**
   ```bash
   sudo oauthseeker setup --access_token $JWT --azure --redirect_url $URL --name $NAME
   ```
6. **Browse to the Administrative Interface:**
   ```bash
   open http://127.0.0.1:8080/admin/
   ```

## 🔍 Admin Interface

OAuthSeeker provides an admin panel where operators can view collected credentials, refresh access tokens, and use the Microsoft Graph API through an embedded instance of GraphRunner. Operators can explore individual credentials, refreshing access tokens as needed to maintain access to Microsoft Graph resources. The built-in GraphRunner interface simplifies navigation to OneDrive, SharePoint, Teams, and Outlook and can be accessed via the “GraphRunner” tab in the OAuthSeeker navigation bar.

## 🎛️ Leveraging Compromised Access Tokens

OAuthSeeker obtains valid Microsoft Graph API credentials inclduing a JWT and refresh token upon successful completion of the OAuth flow with the application. OAuthSeeker automatically perform the token refresh operation every twenty-four hours to ensure that refresh tokens remain active for their entire validity period and aren't revoked early. However, OAuthSeeker doesn't provide any direct means to operationalizing these tokens after they have been obtained through an OAuth consent phishing campaign. However, there are several existing tools which can be used to leverage these tokens for post-exploitation.

### GraphRunner

[GraphRunner](https://www.blackhillsinfosec.com/introducing-graphrunner/) is a post-exploitation toolkit for Microsoft 365, allowing attackers to leverage authenticated access to Microsoft's Graph API. With GraphRunner, operators can search and export data from emails, SharePoint, and Teams, enumerate user permissions, deploy malicious applications, and more. It’s a powerful way to pillage compromised accounts and maintain persistence within a Microsoft 365 environment. Black Hills Information Security originally developed this tool, and they have an informative webcast titled [GraphRunner: A Post-Exploitation Toolset for M365](https://www.youtube.com/watch?v=o29jzC3deS0) discussing the tool's usage and common attack paths. 

### GraphSpy

[GraphSpy](https://insights.spotit.be/2024/04/05/graphspy-the-swiss-army-knife-for-attacking-m365-entra/) is a multipurpose tool designed for advanced red team operations in Microsoft 365, with a local web interface for efficient token management. It enables streamlined access to OneDrive, SharePoint, and Outlook, supporting device code phishing with concurrent code polling. The tool simplifies interactions with Microsoft APIs, allowing attackers to execute custom requests and perform targeted data extraction and persistence operations across projects. More insights are available in a YouTube interview with the GraphSpy author titled [GraphSpy - Offensive Security Tool for Microsoft 365 with Keanu Nys](https://www.youtube.com/watch?v=cDMWw7JgTd0).

### OAuthAzure

OAuthAzure is a utility that can be leveraged alongside OAuthSeeker for post-exploitation and enumeration of resources within an Azure environment. OAuthSeeker allows you to perform a phishing attack where you can request user_impersonation privileges within Microsoft Azure which then allows you to access all Azure resources on behalf of the victim user account. OAuthSeeker by default requests Graph API tokens as the requested token audience for the JWT can either be for the Microsoft Graph API or for Microsoft Azure, but not both at the same time. By default, we request Graph API access within OAuthSeeker, but OAuthAzure can then be leveraged to exchange the obtained JWT and Refresh token for a Microsoft Azure token for access to Azure impersonation capabilities. 

### OAuthPillage

OAuthPillage is a utility included within the OAuthSeeker framework for performing post-exploitation leveraging compromised Microsoft Graph API tokens. This utility allows you to leverage a compromised Microsoft Graph API token with the ability to list user privileges through the User.ReadBasic.All permission to dump all of the information about users available within Microsoft Azure for usage in additional follow-on phishing attacks targeting a victim organization.

## 📚 Documentation

Refer to the **[in-depth setup instructions and documentation](docs/guide.md)** for detailed setup instructions, configuration options, operational security considerations, and usage examples. The **[operational security guide](docs/opsec.md)** documents the operational security considerations when using this capability.

