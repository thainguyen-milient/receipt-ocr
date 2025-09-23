# Vercel Deployment Checklist for Windsurf Project

This document provides a checklist for deploying the Windsurf Project to Vercel and ensuring that login and logout functionality works properly.

## Environment Variables

Make sure the following environment variables are set in your Vercel project settings:

- `NODE_ENV`: Set to `production`
- `JWT_SECRET`: Must be the same as the SSO Gateway's JWT_SECRET
- `SSO_GATEWAY_URL`: Set to `https://sso.receipt-flow.io.vn` (or your production SSO Gateway URL)
- `BASE_URL`: Set to `https://receipt-flow.io.vn` (or your production Windsurf URL)
- `SESSION_SECRET`: A strong, random string for session encryption
- `ALLOWED_ORIGINS`: Comma-separated list of allowed origins, e.g., `https://sso.receipt-flow.io.vn,https://pluriell.receipt-flow.io.vn`

## Domain Configuration

1. **Custom Domain**: Set up a custom domain in Vercel (e.g., `receipt-flow.io.vn`)
2. **SSL Certificate**: Ensure SSL is properly configured (Vercel handles this automatically)
3. **Domain Verification**: Verify domain ownership if required

## Cookie Settings

Ensure cookies are properly configured for cross-domain authentication:

1. All cookies must have:
   - `secure: true` in production
   - `sameSite: 'none'` for cross-domain cookies
   - `domain: '.receipt-flow.io.vn'` (note the leading dot for subdomain support)
   - `path: '/'` to ensure cookies are available across the entire site

2. For HTTP-only cookies:
   - `httpOnly: true`

3. For client-accessible cookies:
   - `httpOnly: false`

## CORS Configuration

Ensure CORS is properly configured:

1. Set `ALLOWED_ORIGINS` environment variable
2. Vercel.json should include proper CORS headers:
   ```json
   "headers": {
     "Access-Control-Allow-Credentials": "true",
     "Access-Control-Allow-Origin": "*",
     "Access-Control-Allow-Methods": "GET,OPTIONS,PATCH,DELETE,POST,PUT",
     "Access-Control-Allow-Headers": "X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization"
   }
   ```

## Static Files

Ensure static files are properly served:

1. Vercel.json should include proper static file configuration:
   ```json
   "builds": [
     {
       "src": "server.js",
       "use": "@vercel/node"
     },
     {
       "src": "public/**",
       "use": "@vercel/static"
     }
   ]
   ```

## Troubleshooting

If login/logout is not working:

1. **Check Browser Console**: Look for any JavaScript errors
2. **Inspect Network Requests**: Ensure redirects are working properly
3. **Check Cookies**: Use browser developer tools to inspect cookies
4. **Check Environment Variables**: Verify they're set correctly in Vercel
5. **Check Server Logs**: Use Vercel logs to see any server-side errors
6. **Clear Browser Cookies**: Sometimes old cookies can cause issues

## Common Issues

1. **JWT_SECRET Mismatch**: Ensure JWT_SECRET is the same across all applications
2. **Cookie Domain Issues**: Make sure cookie domain is set correctly
3. **CORS Issues**: Check for CORS errors in browser console
4. **SSL Issues**: Ensure all redirects use HTTPS in production
5. **Environment Variable Missing**: Check all required environment variables are set

## Deployment Steps

1. Push your code to GitHub
2. Import the project in Vercel
3. Set all required environment variables
4. Deploy the project
5. Set up custom domain if needed
6. Test login and logout functionality
7. Check browser console for any errors
8. Verify cookies are being set correctly
9. Test global logout functionality
