import { useState, useEffect, useRef } from 'react';
import './App.css';

const RESUME_FILE_ID = "1L6PMjM96zToZFfvoyXoxV2D9AKHfxP0v";

const projects = [
  {
    id: 1,
    title: 'Smart Stock',
    subtitle: 'Secure Food Inventory Management',
    description: 'Full-stack MERN application with enterprise-grade security: OAuth 2.0 hybrid auth, out-of-band email verification, and comprehensive input validation for camera-scanned barcode data.',
    tech: ['MongoDB', 'Express.js', 'React', 'Node.js', 'OAuth 2.0', 'JWT', 'bcrypt', 'DigitalOcean'],
    status: 'In Progress',
    github: 'https://github.com/landothedeveloper/smart-stock',
    demo: 'https://smart-stock.food',
    overview: 'Production-ready food inventory management system with barcode scanning, built security-first to protect against OWASP Top 10 vulnerabilities. Deployed on DigitalOcean VPS with SSL/TLS.',
    securityImpact: 'Multi-layered security architecture preventing account takeover, session hijacking, and injection attacks. Defense-in-depth with OAuth 2.0, OOB email verification, JWT token management, and comprehensive input sanitization.',
    highlights: [
      { label: 'Users', value: '200+', note: 'zero security incidents' },
      { label: 'OAuth adoption', value: '67%', note: 'chose Google login over passwords' },
      { label: 'SSL Labs', value: 'A+', note: 'all traffic encrypted' },
    ],
    threatModel: [
      { threat: 'Account Takeover', risk: 'CRITICAL', mitigation: 'OOB email verification for password changes, short-lived JWTs, httpOnly cookies', status: 'Mitigated' },
      { threat: 'Credential Stuffing', risk: 'HIGH', mitigation: 'bcrypt (12 rounds), OAuth 2.0 option, rate limiting on login endpoint', status: 'Mitigated' },
      { threat: 'Man-in-the-Middle', risk: 'HIGH', mitigation: 'Enforced HTTPS/TLS, HSTS headers, secure cookie flags', status: 'Mitigated' },
      { threat: 'XSS', risk: 'MEDIUM', mitigation: 'React auto-escaping, CSP headers, DOMPurify, input validation', status: 'Mitigated' },
      { threat: 'Broken Authentication', risk: 'CRITICAL', mitigation: 'JWT expiry, refresh token rotation, session invalidation on logout', status: 'Mitigated' },
    ],
    deepDive: {
      title: 'Why out-of-band email verification?',
      problem: 'Traditional session-based password changes are vulnerable to session hijacking. An attacker with a valid session (via XSS, CSRF, or fixation) can lock out the legitimate user — no original password needed.',
      solution: 'All critical account operations require email-linked token verification, independent of the web session.',
      points: [
        'Single-use, time-limited tokens (15 min), cryptographically random',
        'Password resets invalidate all existing sessions',
        'New accounts gated behind email confirmation',
        'Attacker needs email access — not just a captured session',
      ]
    },
    code: `const requestPasswordChange = async (req, res) => {
  const { userId, newPassword } = req.body;
  
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = Date.now() + 15 * 60 * 1000; // 15 min
  
  await VerificationToken.create({
    userId,
    token: await bcrypt.hash(token, 12),
    type: 'password-change',
    expiry
  });
  
  await sendEmail({
    to: user.email,
    subject: 'Verify Password Change',
    body: \`Confirm: https://app.com/verify?token=\${token}\`
  });
  
  res.json({ message: 'Verification email sent' });
};`
  },
  {
    id: 2,
    title: 'ShieldCheck',
    subtitle: 'Password Strength Heuristics',
    description: 'Chrome extension providing real-time entropy analysis and common-password blacklisting to mitigate weak credential vulnerabilities — all processed locally with zero data leakage.',
    tech: ['JavaScript ES6', 'Chrome Extension API', 'RegExp', 'HTML5/CSS3'],
    status: 'Completed',
    github: 'https://github.com/LandoTheDeveloper/PasswordStrengthChecker',
    overview: 'Browser-based security tool that evaluates password complexity in real-time. Cross-references inputs against known worst-password lists and calculates entropy based on character diversity and length.',
    securityImpact: 'Directly addresses OWASP Broken Authentication by educating users on password entropy. Acts as a client-side defensive gate against future credential-stuffing attacks.',
    highlights: [
      { label: 'Weak passwords', value: '−85%', note: 'in controlled testing' },
      { label: 'Data sent', value: '0 bytes', note: 'fully local execution' },
      { label: 'Attack surface', value: 'None', note: 'no external API calls' },
    ],
    threatModel: [
      { threat: 'Dictionary Attack', risk: 'HIGH', mitigation: 'Hardcoded common-password blacklist prevents high-risk strings', status: 'Mitigated' },
      { threat: 'Brute Force', risk: 'MEDIUM', mitigation: 'Entropy-based scoring requiring multiple character sets + length', status: 'Mitigated' },
    ],
    deepDive: {
      title: 'Entropy vs. complexity: why length wins',
      problem: 'Users think "Xb2@l!" (6 chars, complex) beats "correctguess" (12 chars, simple). Brute-force search space grows exponentially with length — not character variety.',
      solution: 'Weighted scoring algorithm that prioritizes length while enforcing character variety.',
      points: [
        'Tiered length scoring: 8 chars = standard, 12+ chars = hardened',
        'Regex-based detection across 4 character classes',
        'Immediate rejection for common strings (123456, qwerty, etc.)',
        'Rewards passphrases — statistically harder to crack than complex short passwords',
      ]
    },
    code: `function checkPasswordStrength(password) {
  if (common_passwords.includes(password))
    return { strength: "Blacklisted: Common Password" };
  
  let score = 0;
  
  if (password.length >= 12) score += 2;
  else if (password.length >= 8) score += 1;
  else return { strength: "Insecure: Too Short" };

  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[!@#$%^&*]/.test(password)) score += 1;
  
  return { strength: strengthLevels[Math.min(score, 4)] };
}`
  }
];

const competitions = [
  {
    id: 1,
    name: 'Horse Plinko Cyber Competition',
    abbr: 'HPCC',
    year: '2024',
    type: 'Blue Team Defense',
    description: 'Live blue team defense against active red team attacks. Hardened systems, detected threats, and maintained integrity in real time.',
    skills: ['System Hardening', 'Incident Response', 'Network Defense', 'Log Analysis', 'Threat Detection'],
    takeaways: [
      'Practical experience defending against real attackers under pressure',
      'Prioritizing critical vulnerabilities when time and resources are limited',
      'Rapid security decisions under active attack conditions',
    ]
  },
  {
    id: 2,
    name: 'NCAE Cyber Games',
    abbr: 'NCAE',
    year: '2024',
    type: 'Beginner CTF',
    description: 'National Centers of Academic Excellence competition. Multi-domain challenges across web, crypto, forensics, and more.',
    skills: ['CTF Methodologies', 'Web Security', 'Cryptography', 'Digital Forensics', 'Tool Proficiency'],
    takeaways: [
      'Structured approaches to multi-domain security challenges',
      'Resilience and adaptability when facing unfamiliar problems',
      'Building foundational competitive cybersecurity skills',
    ]
  }
];

const skills = {
  'Engineering': ['React', 'Node.js', 'Express.js', 'MongoDB', 'JavaScript', 'Python', 'REST APIs', 'Git'],
  'Security': ['OAuth 2.0 / JWT', 'OWASP Top 10', 'Threat Modeling', 'Penetration Testing', 'Wireshark', 'Burp Suite', 'Nmap', 'SIEM'],
  'Infrastructure': ['Linux', 'DigitalOcean', 'SSL/TLS', 'Nginx', 'Docker (learning)', 'Cloud Security'],
};

const certifications = [
  { name: 'CompTIA A+', status: 'earned', url: 'https://www.comptia.org/en-us/certifications/a/' },
  { name: 'CompTIA Network+', status: 'earned', url: 'https://www.comptia.org/en-us/certifications/network/' },
  { name: 'Cyber Defense Pro', status: 'earned', url: 'https://www.comptia.org/en-us/certifications/cyber-defense-pro/' },
  { name: 'CompTIA Security+', status: 'earned', url: 'https://www.comptia.org/en-us/certifications/security/' },
];

export default function App() {
  const [section, setSection] = useState('home');
  const [activeProject, setActiveProject] = useState(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    setTimeout(() => setLoaded(true), 100);
  }, []);

  useEffect(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setMenuOpen(false);
  }, [section, activeProject]);

  const nav = [
    { id: 'home', label: 'Home' },
    { id: 'about', label: 'About' },
    { id: 'projects', label: 'Projects' },
    { id: 'competitions', label: 'Competitions' },
    { id: 'contact', label: 'Contact' },
  ];

  return (
    <div className={`app ${loaded ? 'loaded' : ''}`}>
      <div className="grain" />

      <nav className="nav">
        <button className="nav-logo" onClick={() => { setSection('home'); setActiveProject(null); }}>
          LC
        </button>
        <div className={`nav-links ${menuOpen ? 'open' : ''}`}>
          {nav.map(n => (
            <button
              key={n.id}
              className={`nav-link ${section === n.id && !activeProject ? 'active' : ''}`}
              onClick={() => { setSection(n.id); setActiveProject(null); }}
            >
              {n.label}
            </button>
          ))}
        </div>
        <button className="hamburger" onClick={() => setMenuOpen(!menuOpen)}>
          <span /><span /><span />
        </button>
      </nav>

      <main className="main">
        {section === 'home' && !activeProject && <Home setSection={setSection} />}
        {section === 'about' && !activeProject && <About />}
        {section === 'projects' && !activeProject && <Projects setActiveProject={setActiveProject} />}
        {section === 'competitions' && !activeProject && <Competitions />}
        {section === 'contact' && !activeProject && <Contact />}
        {activeProject && <ProjectDetail project={activeProject} back={() => setActiveProject(null)} />}
      </main>

      <footer className="footer">
        <span>© 2026 Landon Craft</span>
        <span className="footer-mono">SHA-256: d4f8c9b2…</span>
      </footer>
    </div>
  );
}

function Home({ setSection }) {
  const roles = ['Software Engineer', 'Security-Minded Builder', 'Full-Stack Developer'];
  const [roleIdx, setRoleIdx] = useState(0);
  const [fade, setFade] = useState(true);

  useEffect(() => {
    const t = setInterval(() => {
      setFade(false);
      setTimeout(() => {
        setRoleIdx(i => (i + 1) % roles.length);
        setFade(true);
      }, 400);
    }, 3000);
    return () => clearInterval(t);
  }, []);

  return (
    <section className="home">
      <div className="home-eyebrow">
        <span className="dot pulse" />
        <span>Available for opportunities</span>
      </div>
      <h1 className="home-name">Landon<br />Craft</h1>
      <p className={`home-role ${fade ? 'fade-in' : 'fade-out'}`}>{roles[roleIdx]}</p>
      <p className="home-desc">
        Full-stack developer building production applications with security baked in — not bolted on.
        MERN stack, OAuth 2.0, threat modeling, and a CompTIA certification stack to back it all up.
      </p>
      <div className="home-actions">
        <button className="btn-primary" onClick={() => setSection('projects')}>View Projects</button>
        <a href={`https://drive.google.com/uc?export=download&id=${RESUME_FILE_ID}`} className="btn-ghost" target="_blank" rel="noopener noreferrer">Download Résumé</a>
      </div>
      <div className="home-links">
        <a href="https://github.com/landothedeveloper" target="_blank" rel="noopener noreferrer">GitHub</a>
        <a href="https://www.linkedin.com/in/landon-craft/" target="_blank" rel="noopener noreferrer">LinkedIn</a>
        <a href="mailto:landoncraftbiz@gmail.com">Email</a>
      </div>

      <div className="home-stats">
        <div className="stat"><span className="stat-num">2</span><span className="stat-label">Projects deployed</span></div>
        <div className="stat"><span className="stat-num">3</span><span className="stat-label">Certifications</span></div>
        <div className="stat"><span className="stat-num">2</span><span className="stat-label">Competitions</span></div>
        <div className="stat"><span className="stat-num">200+</span><span className="stat-label">Users served</span></div>
      </div>
    </section>
  );
}

function About() {
  return (
    <section className="about page-section">
      <div className="page-header">
        <p className="section-label">About</p>
        <h2>Engineering with a<br />security lens</h2>
      </div>

      <div className="about-grid">
        <div className="about-bio">
          <p>
            I'm a software engineer with a deep focus on security — not as two separate disciplines, but as one integrated approach to building software that holds up in the real world.
          </p>
          <p>
            My background spans full-stack web development (MERN), applied security engineering, and competitive cybersecurity. I care about writing code that works, ships, and doesn't get compromised.
          </p>
          <p>
            Currently pursuing CompTIA Security+ and expanding into cloud infrastructure, containerization, and secure DevOps practices.
          </p>
        </div>

        <div className="about-skills">
          {Object.entries(skills).map(([category, list]) => (
            <div key={category} className="skill-group">
              <p className="skill-category">{category}</p>
              <div className="skill-tags">
                {list.map(s => <span key={s} className="skill-tag">{s}</span>)}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="certs-section">
        <p className="section-label">Certifications</p>
        <div className="certs-grid">
          {certifications.map(cert => (
            <a key={cert.name} href={cert.url} target="_blank" rel="noopener noreferrer" className={`cert-card cert-${cert.status}`}>
              <span className="cert-name">{cert.name}</span>
              <span className="cert-status">{cert.status === 'earned' ? 'Earned' : cert.status === 'in-progress' ? 'In Progress' : 'Planned'}</span>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}

function Projects({ setActiveProject }) {
  return (
    <section className="projects page-section">
      <div className="page-header">
        <p className="section-label">Projects</p>
        <h2>Built, shipped,<br />and hardened</h2>
      </div>
      <div className="projects-list">
        {projects.map((p, i) => (
          <div key={p.id} className="project-row" onClick={() => setActiveProject(p)} style={{ animationDelay: `${i * 0.1}s` }}>
            <div className="project-row-left">
              <div className="project-row-num">0{i + 1}</div>
              <div>
                <div className="project-row-title">{p.title}</div>
                <div className="project-row-sub">{p.subtitle}</div>
              </div>
            </div>
            <div className="project-row-right">
              <div className="project-tech-mini">
                {p.tech.slice(0, 3).map(t => <span key={t} className="tech-pill">{t}</span>)}
              </div>
              <span className={`status-badge status-${p.status.toLowerCase().replace(/\s/g, '-')}`}>{p.status}</span>
              <span className="project-arrow">→</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function ProjectDetail({ project: p, back }) {
  return (
    <section className="project-detail page-section">
      <button className="back-btn" onClick={back}>← Back to projects</button>

      <div className="detail-header">
        <div>
          <p className="section-label">{p.subtitle}</p>
          <h2>{p.title}</h2>
        </div>
        <span className={`status-badge status-${p.status.toLowerCase().replace(/\s/g, '-')}`}>{p.status}</span>
      </div>

      <p className="detail-overview">{p.overview}</p>

      <div className="detail-tech">
        {p.tech.map(t => <span key={t} className="tech-pill">{t}</span>)}
      </div>

      <div className="highlights-row">
        {p.highlights.map(h => (
          <div key={h.label} className="highlight-card">
            <span className="highlight-val">{h.value}</span>
            <span className="highlight-label">{h.label}</span>
            <span className="highlight-note">{h.note}</span>
          </div>
        ))}
      </div>

      <div className="detail-block">
        <h3>Security impact</h3>
        <p>{p.securityImpact}</p>
      </div>

      <div className="detail-block">
        <h3>{p.deepDive.title}</h3>
        <div className="deep-dive">
          <div className="dd-row">
            <span className="dd-label problem">Problem</span>
            <p>{p.deepDive.problem}</p>
          </div>
          <div className="dd-row">
            <span className="dd-label solution">Solution</span>
            <p>{p.deepDive.solution}</p>
          </div>
          <ul className="dd-points">
            {p.deepDive.points.map(pt => <li key={pt}>{pt}</li>)}
          </ul>
        </div>
      </div>

      <div className="detail-block">
        <h3>Threat model</h3>
        <div className="threat-table-wrap">
          <table className="threat-table">
            <thead>
              <tr>
                <th>Threat</th>
                <th>Risk</th>
                <th>Mitigation</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {p.threatModel.map(t => (
                <tr key={t.threat}>
                  <td>{t.threat}</td>
                  <td><span className={`risk-badge risk-${t.risk.toLowerCase()}`}>{t.risk}</span></td>
                  <td className="mitigation-cell">{t.mitigation}</td>
                  <td><span className="mitigated">✓ {t.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="detail-block">
        <h3>Code example</h3>
        <pre className="code-block"><code>{p.code}</code></pre>
      </div>

      <div className="detail-links">
        {p.github && <a href={p.github} className="btn-primary" target="_blank" rel="noopener noreferrer">View on GitHub</a>}
        {p.demo && <a href={p.demo} className="btn-ghost" target="_blank" rel="noopener noreferrer">Live Demo</a>}
      </div>
    </section>
  );
}

function Competitions() {
  return (
    <section className="competitions page-section">
      <div className="page-header">
        <p className="section-label">Competitions</p>
        <h2>Tested under<br />pressure</h2>
      </div>
      <div className="comp-grid">
        {competitions.map(c => (
          <div key={c.id} className="comp-card">
            <div className="comp-top">
              <div className="comp-abbr">{c.abbr}</div>
              <div>
                <h3>{c.name}</h3>
                <div className="comp-meta">
                  <span>{c.year}</span>
                  <span className="sep">·</span>
                  <span>{c.type}</span>
                </div>
              </div>
            </div>
            <p className="comp-desc">{c.description}</p>
            <div className="comp-skills">
              {c.skills.map(s => <span key={s} className="tech-pill">{s}</span>)}
            </div>
            <div className="comp-takeaways">
              <p className="takeaway-label">Key takeaways</p>
              <ul>
                {c.takeaways.map(t => <li key={t}>{t}</li>)}
              </ul>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Contact() {
  return (
    <section className="contact page-section">
      <div className="page-header">
        <p className="section-label">Contact</p>
        <h2>Let's build<br />something</h2>
      </div>
      <p className="contact-intro">
        Open to full-stack engineering roles, security-adjacent positions, and interesting projects.
        Feel free to reach out directly.
      </p>
      <div className="contact-methods">
        <a href="mailto:landoncraftbiz@gmail.com" className="contact-row">
          <span className="contact-type">Email</span>
          <span className="contact-val">landoncraftbiz@gmail.com</span>
          <span className="contact-arrow">→</span>
        </a>
        <a href="https://www.linkedin.com/in/landon-craft/" target="_blank" rel="noopener noreferrer" className="contact-row">
          <span className="contact-type">LinkedIn</span>
          <span className="contact-val">linkedin.com/in/landon-craft</span>
          <span className="contact-arrow">→</span>
        </a>
        <a href="https://github.com/landothedeveloper" target="_blank" rel="noopener noreferrer" className="contact-row">
          <span className="contact-type">GitHub</span>
          <span className="contact-val">github.com/landothedeveloper</span>
          <span className="contact-arrow">→</span>
        </a>
      </div>
    </section>
  );
}
