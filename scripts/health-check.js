// Daily freshness check for every external API/service VerifyGuard depends on,
// plus TLS cert health for both custom domains. A non-zero exit makes the
// GitHub Action run "fail", which triggers GitHub's default email
// notification to the repo owner — no separate alerting service needed.
const tls = require('tls');

const problems = [];
const ok = [];

async function checkSightengine() {
  const url = `https://api.sightengine.com/1.0/check.json?models=nudity-2.1&url=https://sightengine.com/assets/img/examples/example5.jpg&api_user=${process.env.SIGHTENGINE_USER}&api_secret=${process.env.SIGHTENGINE_SECRET}`;
  const res = await fetch(url);
  const data = await res.json();
  if (data.status === 'failure') {
    problems.push(`Sightengine: ${data.error?.message || 'unknown error'}`);
  } else {
    ok.push('Sightengine key valid');
  }
}

async function checkGNews() {
  const res = await fetch(`https://gnews.io/api/v4/top-headlines?category=general&lang=en&max=1&apikey=${process.env.GNEWS_KEY}`);
  const data = await res.json();
  if (res.status === 401 || res.status === 403) {
    problems.push(`GNews: auth/quota error (HTTP ${res.status}) — ${data.errors?.[0] || ''}`);
  } else if (!res.ok) {
    problems.push(`GNews: unexpected HTTP ${res.status}`);
  } else {
    ok.push('GNews key valid');
  }
}

async function checkVirusTotal() {
  const res = await fetch('https://www.virustotal.com/api/v3/domains/example.com', {
    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
  });
  if (res.status === 401 || res.status === 403) {
    problems.push(`VirusTotal: auth error (HTTP ${res.status})`);
  } else if (res.status === 429) {
    problems.push('VirusTotal: rate/quota limit hit (HTTP 429)');
  } else if (!res.ok) {
    problems.push(`VirusTotal: unexpected HTTP ${res.status}`);
  } else {
    ok.push('VirusTotal key valid');
  }
}

async function checkAnthropic() {
  const res = await fetch('https://api.anthropic.com/v1/models', {
    headers: {
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
  });
  if (!res.ok) {
    problems.push(`Anthropic: key check failed (HTTP ${res.status})`);
  } else {
    ok.push('Anthropic key valid (note: this does not check credit balance — enable low-balance email alerts in platform.claude.com/settings/billing)');
  }
}

async function checkRailwayServer() {
  const res = await fetch('https://clever-bravery-production-2d5f.up.railway.app/health');
  const data = await res.json().catch(() => null);
  if (!res.ok || data?.status !== 'ok') {
    problems.push(`Railway server: /health did not return ok (HTTP ${res.status})`);
  } else {
    ok.push('Railway server healthy');
  }
}

function checkCert(host) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, host, { servername: host, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate();
      const expires = new Date(cert.valid_to);
      const daysLeft = Math.round((expires - Date.now()) / 86400000);
      const cnMatches = cert.subject?.CN === host || cert.subject?.CN === `*.${host.split('.').slice(-2).join('.')}`
        ? true
        : cert.subject?.CN === host;
      if (!cert.subject?.CN?.includes(host.split('.').slice(-2).join('.')) && cert.subject?.CN !== host) {
        problems.push(`${host}: serving wrong certificate (CN=${cert.subject?.CN}) — likely the platform's fallback cert, not one issued for this domain`);
      } else if (daysLeft < 14) {
        problems.push(`${host}: certificate expires in ${daysLeft} days`);
      } else {
        ok.push(`${host}: cert valid, CN=${cert.subject?.CN}, ${daysLeft} days left`);
      }
      socket.end();
      resolve();
    });
    socket.on('error', (err) => {
      problems.push(`${host}: TLS connection failed — ${err.message}`);
      resolve();
    });
    socket.on('timeout', () => {
      problems.push(`${host}: TLS connection timed out`);
      socket.destroy();
      resolve();
    });
  });
}

async function checkGitHubPages(owner, repo) {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}/pages`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
    },
  });
  if (!res.ok) {
    problems.push(`${repo}: Pages API request failed (HTTP ${res.status})`);
    return;
  }
  const data = await res.json();
  const certState = data.https_certificate?.state;
  if (!certState || (certState !== 'issued' && certState !== 'approved')) {
    problems.push(`${repo}: GitHub Pages HTTPS cert state is "${certState ?? 'unknown'}" (not issued)`);
  } else {
    ok.push(`${repo}: Pages HTTPS cert state "${certState}"`);
  }
}

async function main() {
  await Promise.all([
    checkSightengine().catch((e) => problems.push(`Sightengine: ${e.message}`)),
    checkGNews().catch((e) => problems.push(`GNews: ${e.message}`)),
    checkVirusTotal().catch((e) => problems.push(`VirusTotal: ${e.message}`)),
    checkAnthropic().catch((e) => problems.push(`Anthropic: ${e.message}`)),
    checkRailwayServer().catch((e) => problems.push(`Railway server: ${e.message}`)),
    checkCert('officialverifyguard.com'),
    checkCert('scampedia.net'),
    checkGitHubPages('nolanickelliott02-collab', 'officialverifyguard').catch((e) => problems.push(`Pages check: ${e.message}`)),
  ]);

  console.log('--- OK ---');
  ok.forEach((line) => console.log('✓', line));

  if (problems.length > 0) {
    console.log('\n--- PROBLEMS ---');
    problems.forEach((line) => console.log('✗', line));
    process.exitCode = 1;
  } else {
    console.log('\nAll checks passed.');
  }
}

main();
