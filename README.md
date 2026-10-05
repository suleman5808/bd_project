# MySQL Registration and Login for Netlify

A small registration/login site for a GitHub repository deployed on Netlify. The Netlify Function talks to an online MySQL database; database credentials stay in Netlify environment variables. A successful registration or login opens `public/index.html`.

## 1. Create the MySQL table

Run `database.sql` using MySQL Command Line Client or your hosted MySQL provider's SQL console. If your provider already created a database for you, select that database and run only the `CREATE TABLE` statement.

The database must be hosted online. A MySQL server running only on your computer (`localhost`) cannot be reached by a deployed Netlify site.

## 2. Add this project to GitHub

Upload the project files and folders to your GitHub repository. If you already have a home page in your repository, put its page content and assets inside `public/`. Keep the session-checking script in `public/index.html`, so the site redirects users who are not logged in to the registration/login page.

## 3. Connect the repository to Netlify

In Netlify, import the GitHub repository. The included `netlify.toml` sets the publish directory and Functions directory. The site root (`/`) opens `auth.html`. Successful registration or login redirects to `/index.html`.

## 4. Set Netlify environment variables

In your Netlify site's environment variable settings, add these values and make sure they are available to Functions at runtime:

| Name | Value |
| --- | --- |
| `DB_HOST` | Hostname from your online MySQL provider |
| `DB_PORT` | MySQL port, usually `3306` |
| `DB_NAME` | `registration_db` or the database name provided to you |
| `DB_USER` | MySQL username |
| `DB_PASSWORD` | MySQL password |
| `DB_SSL` | `true` if required by your provider; otherwise `false` |
| `SESSION_SECRET` | A private random value of at least 32 characters |

You can generate a session secret in a terminal with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Do not put real database credentials or the session secret in GitHub, HTML, or `netlify.toml`. After setting the variables, deploy or redeploy the site.

## 5. Try it

Open the Netlify site URL. Create an account with a name, email, and password of at least 8 characters. The password is stored as a bcrypt hash, not as plain text. After registration, the browser opens the index page. Signing out returns to the login page.

The sample index page is static. Its browser-side check controls the demo page flow; do not put private information directly in static HTML. Any private data API must verify the session in its server-side function.
