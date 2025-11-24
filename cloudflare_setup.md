# Cloudflare Pages Setup Guide for Soqu.org

This guide will walk you through deploying your `soqu-web` directory to Cloudflare Pages and connecting your domains.

## Prerequisites
- You have a Cloudflare account.
- You have access to the `soqucoin/soqucoin` GitHub repository.
- You have pushed the latest changes (including `soqu-web/`) to GitHub.

## Step 1: Connect GitHub to Cloudflare Pages

1.  Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com).
2.  In the sidebar, click **Workers & Pages**.
3.  Click the blue **Create Application** button.
4.  Click the **Pages** tab.
5.  Click **Connect to Git**.
6.  Select the **GitHub** tab and click **Connect GitHub**.
    *   *Note: You may need to authorize Cloudflare to access your GitHub account/organizations.*
7.  Select the `soqucoin/soqucoin` repository.
8.  Click **Begin setup**.

## Step 2: Configure the Build

1.  **Project Name**: Enter `soqu-org` (or your preferred name).
2.  **Production Branch**: Select `soqucoin-genesis` (or `main` if you merged it).
3.  **Framework Preset**: Select **None** (since this is a static HTML site).
4.  **Build Command**: Leave blank.
5.  **Build Output Directory**: Enter `soqu-web`.
    *   *Crucial Step: This tells Cloudflare to serve the files inside the `soqu-web` folder, not the root of the repo.*
6.  Click **Save and Deploy**.

Cloudflare will now clone your repo and deploy the site. This usually takes less than a minute.

## Step 3: Connect Custom Domains

Once the deployment is successful, you will see a success message and a `*.pages.dev` URL. Now, let's connect your domains.

1.  Go to the **Custom Domains** tab in your Pages project settings.
2.  Click **Set up a custom domain**.
3.  Enter `soqu.org` and click **Continue**.
4.  Cloudflare will prompt you to update DNS records. Since your domains are already on Cloudflare, this is automatic. Click **Activate Domain**.
5.  Repeat this process for `www.soqu.org`.

### Redirecting Other Domains (soqucoin.com, soqucoin.org)

To redirect `soqucoin.com` and `soqucoin.org` to `soqu.org`:

1.  Go to the Cloudflare Dashboard home and select `soqucoin.com`.
2.  Go to **Rules** > **Redirect Rules**.
3.  Click **Create Rule**.
4.  **Name**: "Redirect to soqu.org".
5.  **When incoming requests match**: Select **All incoming requests**.
6.  **Then**:
    *   **Type**: Dynamic
    *   **Expression**: `concat("https://soqu.org", http.request.uri.path)`
    *   **Status Code**: 301 (Permanent Redirect)
    *   **Preserve query string**: Checked.
7.  Click **Deploy**.
8.  Repeat for `soqucoin.org`.

## Verification

Visit `https://soqu.org`. You should see the new website with the logo and whitepaper.
