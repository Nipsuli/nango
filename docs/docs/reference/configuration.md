# Advanced Configurations

## Connection Metadata {#connection-metadata}

Some API Providers provide important metadata during the OAuth flow that needs to be captured.

For example, Braintree provides the subdomain that needs to be used to perform API requests. Fitbit provides the specific scopes that the user agreed to grant, etc.

This information is captured in the `metadata` field of the Connection object.

You can verify which metadata is captured for your API Provider in the [providers.yaml](https://nango.dev/oauth-providers) file under the `redirect_uri_metadata` and `token_response_metadata` fields.

## Custom Callback URL

Nango Cloud supports custom callback URLs so that your OAuth Apps redirect to your domain instead of `https://api.nango.dev`. Reach out directly on the [Slack community](https://nango.dev/slack) to enable it for your account.

Nango Self-Hosted also supports custom callback URLs (cf. [docs](../nango-deploy/oss-instructions.md#custom-urls)).

## Something not working as expected? Need help?

If you run into any trouble with Nango or have any questions please do not hesitate to contact us - we are happy to help!

Please join our [Slack community](https://nango.dev/slack), where we are very active, and we will do our best to help you fast.
