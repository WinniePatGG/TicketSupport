const nodemailer = require('nodemailer');
const https = require('https');

const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || '';

function buildTransport() {
  const host = process.env.SMTP_HOST;
  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : undefined;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (host && user && pass) {
    return nodemailer.createTransport({
      host,
      port: port || 587,
      secure: Boolean(process.env.SMTP_SECURE === '1' || process.env.SMTP_SECURE === 'true'),
      auth: { user, pass },
    });
  }
  return null; // fallback to console logging
}

const transporter = buildTransport();

async function sendVerificationEmail(toEmail, token, name) {
  const verifyUrl = `${APP_BASE_URL}/verify/${token}`;
  const from = process.env.SMTP_FROM || 'no-reply@ticketsupport.local';
  const subject = 'Verify your email address';
  const text = `Hi${name ? ' ' + name : ''},\n\nPlease verify your email to activate your account.\n\nVerify link: ${verifyUrl}\n\nIf you did not create an account, you can ignore this email.`;
  const html = `
    <p>Hi${name ? ' ' + escapeHtml(name) : ''},</p>
    <p>Please verify your email to activate your account.</p>
    <p><a href="${verifyUrl}">Verify your email</a></p>
    <p>If the button above does not work, copy and paste this URL into your browser:</p>
    <p><code>${verifyUrl}</code></p>
    <hr/>
    <p>If you did not create an account, you can ignore this email.</p>
  `;

  if (transporter) {
    await transporter.sendMail({ from, to: toEmail, subject, text, html });
    return; // Prefer SMTP when configured
  }
  if (DISCORD_WEBHOOK_URL) {
    try {
      await sendToDiscordWebhook(DISCORD_WEBHOOK_URL, {
        verifyUrl,
        toEmail,
        name,
      });
      return;
    } catch (e) {
      console.error('Failed to send verification to Discord webhook:', e.message);
    }
  }
  // Final fallback: log the link to the server console
  console.log('[Email Verification] No SMTP/Discord configured. Share this link with the user:', verifyUrl);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function sendToDiscordWebhook(webhookUrl, details) {
  const { verifyUrl, toEmail, name } = details || {};
  const payload = {
    username: 'TicketSupport',
    avatar_url: 'https://raw.githubusercontent.com/twitter/twemoji/master/assets/72x72/2709.png',
    content: `Email verification${toEmail ? ` for ${toEmail}` : ''}`,
    embeds: [
      {
        title: 'Verify your email',
        description: `[Click here to verify](${verifyUrl})`,
        color: 0x5865f2,
        fields: [
          toEmail ? { name: 'Email', value: String(toEmail), inline: true } : undefined,
          name ? { name: 'Name', value: String(name), inline: true } : undefined,
          { name: 'Link', value: verifyUrl },
        ].filter(Boolean),
        timestamp: new Date().toISOString(),
      },
    ],
  };

  const data = JSON.stringify(payload);
  const u = new URL(webhookUrl);
  const options = {
    method: 'POST',
    hostname: u.hostname,
    path: `${u.pathname}${u.search || ''}`,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(data),
    },
  };

  await new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      // Drain response to free memory
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) return resolve();
        return reject(new Error(`HTTP ${res.statusCode}: ${body}`));
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

module.exports = { sendVerificationEmail, APP_BASE_URL };
