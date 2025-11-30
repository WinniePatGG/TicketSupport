# WinniePatGG's Ticket Support

##  Environment Variables (.env)
### Server Variables
| Key            |                     Value                      |
|:---------------|:----------------------------------------------:|
| PORT           | Default: 3000 ; Port the service is running on |
| SESSION_SECRET |  Long Random String that is used for sessions  |

### Admin Seeding (Initial Admin Account)

| Key            |                              Value                              |
|:---------------|:---------------------------------------------------------------:|
| ADMIN_EMAIL    | Default: admin@example.com; Email for the initial admin account |
| ADMIN_PASSWORD |    Default: admin123; Password for the initial admin account    |

### Google OAuth 2.0

| Key                  |                 Value                  |
|:---------------------|:--------------------------------------:|
| GOOGLE_CLIENT_ID     |  Email for the initial admin account   |
| GOOGLE_CLIENT_SECRET | Password for the initial admin account |
| GOOGLE_CALLBACK_URL  | Password for the initial admin account |

### SMTP (Email)

| Key         |                             Value                              |
|:------------|:--------------------------------------------------------------:|
| SMTP_HOST   |                         Your SMTP Host                         |
| SMTP_PORT   |                         Your SMTP Port                         |
| SMTP_USER   |                         Your SMTP User                         |
| SMTP_PASS   |                    Your SMTP User password                     |
| SMTP_SECURE |                         true or false                          |
| SMTP_FROM   | Default: "Support <no-reply@yourdomain.com>"; The from message |

### Discord webhook

| Key                 |             Value              |
|:--------------------|:------------------------------:|
| DISCORD_WEBHOOK_URL | The url of you discord webhook |

# Information
The Service creates a support.sqlite3 file that stores all data the service needs.

# Getting Started
### Docker
- Create a folder `support-service`
- Download the `docker-compose.yml` from the repo
- Create a new directory `app`
- Put all files into the `app` directory
- Run `docker compose up -d` in the directory with the `docker-compose.yml`

### Standalone
- `git clone https://github.com/WinniePatGG/TicketSupport.git`
- `cd TicketSupport`
- `npm install`
- `npm run start`

# Important Notes

- The Google login button appears only when GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set.
- If you change PORT, also update GOOGLE_CALLBACK_URL and the redirect URI in Google Cloud.
- I couldn't test the SMTP stuff, but it should work (I hope). If not, let me know.