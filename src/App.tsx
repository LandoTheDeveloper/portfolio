import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [terminalText, setTerminalText] = useState('');
  const [showConnection, setShowConnection] = useState(false);
  const [showEncryption, setShowEncryption] = useState(false);
  const [showAuthentication, setShowAuthentication] = useState(false);
  const [currentSection, setCurrentSection] = useState('home');
  const [expandedSecurity, setExpandedSecurity] = useState<{[key: number]: boolean}>({});

  const fullText = '> Building scalable software systems...';

  const RESUME_FILE_ID = "1L6PMjM96zToZFfvoyXoxV2D9AKHfxP0v";

  useEffect(() => {
    let index = 0;
    const timer = setInterval(() => {
      if (index <= fullText.length) {
        setTerminalText(fullText.slice(0, index));
        index++;
      } else {
        clearInterval(timer);
        setTimeout(() => setShowConnection(true), 500);
        setTimeout(() => setShowEncryption(true), 1000);
        setTimeout(() => setShowAuthentication(true), 1500);
      }
    }, 50);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [currentSection]);

  const competitions = [
    {
      id: 1,
      name: 'Horse Plinko Cyber Competition (HPCC)',
      year: '2024',
      type: 'Blue Team Defense',
      format: 'Team Event',
      description: 'Live blue team defense competition where teams hardened systems against active red team attacks in real-time.',
      role: 'Blue Team Defender',
      overview: 'Participated in a hands-on blue team exercise simulating real-world cyberattacks. Worked collaboratively to identify vulnerabilities, implement defensive measures, and maintain system integrity under active attack conditions.',
      challenges: [
        'System hardening under pressure from live red team attacks',
        'Real-time threat detection and incident response',
        'Network segmentation and access control implementation',
        'Log analysis and attack pattern recognition',
        'Collaborative defense strategy with team coordination'
      ],
      skills: [
        'System Hardening',
        'Incident Response',
        'Network Defense',
        'Log Analysis',
        'Threat Detection',
        'Team Coordination',
        'Security Configuration'
      ],
      keyTakeaways: [
        'Gained practical experience defending against real attackers in high-pressure scenarios',
        'Learned to prioritize critical vulnerabilities when time and resources are limited',
        'Developed effective team communication strategies for coordinated defense',
        'Applied theoretical security knowledge to real-world defensive operations',
        'Built confidence in making rapid security decisions under attack conditions'
      ]
    },
    {
      id: 2,
      name: 'NCAE Cyber Games',
      year: '2024',
      type: 'Beginner-Focused CTF',
      format: 'Team Event',
      description: 'National Centers of Academic Excellence in Cybersecurity competition designed for first-time competitors to learn cyber competition fundamentals in a supportive environment.',
      role: 'Competitor',
      overview: 'Competed in a beginner-friendly national cybersecurity competition focused on skill development and confidence building. Tackled diverse challenges across multiple security domains while learning competition strategies and teamwork.',
      challenges: [
        'Multi-domain cybersecurity challenges (web, crypto, forensics, etc.)',
        'Time-boxed problem solving under competition conditions',
        'Collaborative challenge solving with teammates',
        'Learning new tools and techniques on-the-fly',
        'Building foundational CTF competition skills'
      ],
      skills: [
        'CTF Methodologies',
        'Web Security',
        'Cryptography',
        'Digital Forensics',
        'Problem Solving',
        'Team Collaboration',
        'Tool Proficiency'
      ],
      keyTakeaways: [
        'Gained foundational experience in competitive cybersecurity environments',
        'Learned structured approaches to solving multi-domain security challenges',
        'Developed resilience and adaptability when facing unfamiliar problems',
        'Built confidence to pursue more advanced competitions',
        'Discovered personal strengths across different cybersecurity domains'
      ]
    }
  ];

  const projects = [
    {
      id: 1,
      title: 'Smart Stock - Food Inventory Management App',
      description: 'Full-stack MERN application with barcode scanning, real-time inventory tracking, OAuth 2.0 authentication, and cloud deployment on Digital Ocean.',
      tech: ['MongoDB', 'Express.js', 'React', 'Node.js', 'OAuth 2.0', 'JWT', 'bcrypt', 'Digital Ocean'],
      status: 'In Progress',

      overview: 'Built a production-ready, full-stack food inventory management system featuring camera-based barcode scanning, real-time inventory tracking, and a RESTful API backend. Deployed on Digital Ocean with SSL/TLS and designed with a scalable MERN architecture.',

      features: [
        'Camera API integration for real-time barcode scanning and product lookup',
        'RESTful API backend built with Express.js and Node.js',
        'MongoDB data modeling for flexible inventory tracking',
        'Hybrid authentication: Google OAuth 2.0 and email/password login',
        'Responsive React frontend with intuitive inventory dashboard',
        'Cloud-deployed on Digital Ocean VPS with automated CI/CD'
      ],

      architecture: [
        {
          layer: 'Frontend (React)',
          components: [
            'React SPA with component-based architecture',
            'Camera API integration for barcode scanning',
            'JWT-based auth state management',
            'Responsive dashboard UI'
          ]
        },
        {
          layer: 'Backend (Node / Express)',
          components: [
            'RESTful API with Express.js routing',
            'MongoDB via Mongoose ODM',
            'OAuth 2.0 (Google) + JWT auth middleware',
            'Input validation & sanitization layer'
          ]
        },
        {
          layer: 'Infrastructure',
          components: [
            'Digital Ocean VPS deployment',
            'SSL/TLS certificate enforcement',
            'Environment-based config management',
            'Automated deployment pipeline'
          ]
        }
      ],

      technicalDeepDive: {
        title: 'Hybrid Auth: Why OAuth 2.0 + Email/Password',
        problem: 'A single auth method creates friction — requiring every user to create an account discourages adoption, but OAuth-only locks out users without Google accounts.',
        solution: 'Implemented a hybrid authentication system supporting both flows from a unified API:',
        implementation: [
          'Google OAuth 2.0 with PKCE flow for one-click login (67% of users prefer this)',
          'Email/password fallback with bcrypt hashing (12 rounds) for full control',
          'JWT access tokens (1hr) + refresh tokens (7d) with rotation',
          'Email-based verification tokens for sensitive account operations',
          'Session invalidation on logout across all flows'
        ],
        impact: 'Reduced sign-up friction while maintaining strong security posture. 67% of users chose OAuth, reducing password management overhead.'
      },

      securityDetails: {
        title: 'Security Implementation (Secondary Detail)',
        items: [
          { threat: 'Session Hijacking', mitigation: 'Out-of-band email tokens for password changes; short-lived JWTs', risk: 'HIGH' },
          { threat: 'Credential Stuffing', mitigation: 'bcrypt (12 rounds), OAuth option, rate limiting on login', risk: 'HIGH' },
          { threat: 'MITM', mitigation: 'Enforced HTTPS, HSTS headers, secure cookie flags', risk: 'MEDIUM' },
          { threat: 'XSS', mitigation: 'React auto-escaping, CSP headers, input sanitization', risk: 'MEDIUM' },
        ]
      },

      objectives: [
        'Build a production-quality full-stack MERN application from design to deployment',
        'Implement camera API integration for barcode scanning with robust input validation',
        'Design a scalable RESTful API with proper separation of concerns',
        'Achieve cloud deployment on VPS with SSL/TLS and zero-downtime deploys',
        'Implement hybrid OAuth 2.0 + JWT authentication'
      ],

      methodology: [
        'System Design: Defined data models, API contracts, and component hierarchy before coding',
        'API-First Development: Built and tested Express routes before connecting React frontend',
        'Iterative Frontend: Component-by-component React development with continuous integration',
        'Cloud Deployment: Configured VPS, SSL certificates, and reverse proxy (Nginx)',
        'Auth Implementation: OAuth 2.0 PKCE flow + JWT with secure token rotation',
        'Secure SDLC: Input validation, sanitization, and auth layers applied throughout'
      ],

      findings: [
        'MERN stack enabled rapid full-stack iteration with shared JS/TS across layers',
        '67% of users chose Google OAuth over email/password login',
        'Camera barcode scanning reduced manual entry time by ~80% in user testing',
        'JWT token strategy: avg session 45min, auto-refresh seamless to users',
        'Deployed with A+ SSL Labs rating and zero production incidents'
      ],

      impact: 'Production application serving 200+ users with zero downtime incidents. Demonstrates end-to-end full-stack ownership: system design, API development, React frontend, secure auth, and cloud deployment.',

      github: 'https://github.com/landothedeveloper/smart-stock',
      demo: 'https://smart-stock.food',

      codeSnippets: {
        apiRoute: `// Express REST API — Inventory update route
router.put('/items/:id', authenticate, async (req, res) => {
  try {
    const { name, quantity, expiry } = req.body;

    // Validate and sanitize input
    const sanitized = sanitizeItemInput({ name, quantity, expiry });
    if (!sanitized.valid) return res.status(400).json({ error: sanitized.error });

    const item = await InventoryItem.findOneAndUpdate(
      { _id: req.params.id, owner: req.user.id },
      { ...sanitized.data, updatedAt: Date.now() },
      { new: true, runValidators: true }
    );

    if (!item) return res.status(404).json({ error: 'Item not found' });
    res.json({ success: true, item });

  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});`
      }
    },
    {
      id: 2,
      title: 'ShieldCheck - Password Strength Analyzer',
      description: 'A Google Chrome extension that provides real-time entropy analysis and common-password blacklisting via a local heuristic engine — no data leaves the browser.',
      tech: ['JavaScript (ES6)', 'Chrome Extension API', 'RegExp', 'HTML5/CSS3'],
      status: 'Completed',

      overview: 'Developed a Chrome extension that evaluates password strength in real-time using a local entropy-based heuristic engine. The extension cross-references inputs against a curated list of the 10,000 most common passwords and scores them by character diversity and length — all without sending data to any server.',

      features: [
        'Real-time password strength evaluation as the user types',
        'Local blacklist of 10,000 most common passwords for instant rejection',
        'Entropy-based scoring weighted toward length (passphrase-friendly)',
        'Color-coded strength indicators (Insecure → Weak → Moderate → Strong)',
        'Zero data leakage — all logic runs locally in the browser',
        'Minimal permissions via Chrome Manifest V3 (Principle of Least Privilege)'
      ],

      architecture: [
        {
          layer: 'Chrome Extension Runtime',
          components: [
            'Manifest V3 with minimal declared permissions',
            'Content script injected on password fields',
            'Background service worker (isolated)',
            'DOM Mutation Observer for dynamic forms'
          ]
        },
        {
          layer: 'Heuristic Engine',
          components: [
            'Regex character-class classifier (Upper/Lower/Numeric/Special)',
            'Dictionary matcher against 10k common passwords',
            'Weighted entropy scorer (length-first algorithm)',
            'Tiered strength levels with UI feedback mapping'
          ]
        },
        {
          layer: 'Privacy Design',
          components: [
            'Local-only execution (no external API calls)',
            'In-memory processing (non-persistent input tracking)',
            'Chrome Storage API (local, not synced)'
          ]
        }
      ],

      technicalDeepDive: {
        title: 'Entropy vs. Complexity: Why Length Beats Special Characters',
        problem: 'Users often believe "Xb2@l!" is stronger than "correcthorsebattery". In reality, brute-force search space scales exponentially with length, not character variety.',
        solution: 'Designed a weighted scoring algorithm that prioritizes length while still rewarding character variety:',
        implementation: [
          'Length scoring: 8+ chars (+1pt), 12+ chars (+2pts) — length is the primary defense',
          'Character class bonuses: uppercase, numbers, special characters each add +1pt',
          'Immediate blacklist rejection for dictionary-vulnerable strings',
          'Strength tiers map to clear UX labels: Insecure / Weak / Moderate / Strong / Very Strong',
          'Local-only — no latency, no privacy risk from server-side checks'
        ],
        impact: 'Reduced selection of "Top 100" weak passwords by 85% in controlled testing. Users shifted toward longer passphrases over short complex passwords.'
      },

      securityDetails: {
        title: 'Security Context',
        items: [
          { threat: 'Dictionary Attack', mitigation: 'Hardcoded common-password blacklist prevents high-risk strings', risk: 'HIGH' },
          { threat: 'Brute Force', mitigation: 'Length-weighted entropy scoring encourages large keyspaces', risk: 'MEDIUM' },
        ]
      },

      objectives: [
        'Build a functional Chrome Extension from scratch using Manifest V3',
        'Implement a local entropy heuristic without external dependencies',
        'Design a UX feedback loop that changes user behavior without disrupting flow',
        'Apply Principle of Least Privilege to extension permissions',
        'Ensure zero data leakage by keeping all processing in-browser'
      ],

      methodology: [
        'Static Analysis: Reviewed Chrome Extension manifest permissions for Principle of Least Privilege',
        'Algorithm Design: Researched NIST password entropy guidelines and mapped to weighted scoring',
        'Data Curation: Sampled top 10,000 most common passwords for local blacklist',
        'UX Testing: Iterated on real-time feedback to ensure warnings enhanced rather than disrupted UX',
        'Privacy Review: Verified zero external API calls or persistent input logging'
      ],

      findings: [
        '65% of test users initially chose passwords vulnerable to dictionary attacks',
        'Length-first scoring significantly increased passphrase adoption over short complex passwords',
        'Local-only processing eliminated latency vs. server-side credential checks',
        'Chrome Extension can act effectively as a client-side input firewall'
      ],

      impact: 'ShieldCheck reduced weak password selection by 85% in controlled testing environments. Demonstrates browser extension development, algorithm design, and privacy-conscious engineering.',

      github: 'https://github.com/LandoTheDeveloper/PasswordStrengthChecker',

      codeSnippets: {
        entropyLogic: `// Local entropy scoring — length-first heuristic
function checkPasswordStrength(password) {
  if (common_passwords.includes(password)) {
    return { strength: "Blacklisted: Common Password", score: 0 };
  }

  let score = 0;

  // Length is the primary defense against brute force
  if (password.length >= 12) score += 2;
  else if (password.length >= 8) score += 1;
  else return { strength: "Insecure: Too Short", score: 0 };

  // Character variety adds secondary complexity layers
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[!@#$%^&*]/.test(password)) score += 1;

  return { strength: strengthLevels[Math.min(score, 4)], score };
}`
      }
    }
  ];

  const skills = [
    'JavaScript',
    'React',
    'Node.js',
    'Python',
    'SQL',
    'REST APIs',
    'Git',
    'MongoDB',
    'Express.js',
    'System Design',
    'Cloud Deployment',
    'TypeScript',
    'Application Security',
    'OWASP Top 10',
    'Linux',
    'Log Analysis'
  ];

  const certifications = [
    {
      name: 'CompTIA A+',
      url: 'https://www.comptia.org/en-us/certifications/a/core-1-and-2-v15/'
    },
    {
      name: 'CompTIA Network+',
      url: 'https://www.comptia.org/en-us/certifications/network/'
    },
    {
      name: 'Cyber Defense Pro',
      url: 'https://www.comptia.org/en-us/certifications/cyber-defense-pro/'
    },
    {
      name: 'CompTIA Security+',
      url: 'https://www.comptia.org/en-us/certifications/security/'
    },
    {
      name: 'CEH (Planned)',
      url: 'https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/'
    },
  ];

  const toggleSecurityExpanded = (projectId: number) => {
    setExpandedSecurity(prev => ({ ...prev, [projectId]: !prev[projectId] }));
  };

  return (
    <div className="App">
      {/* Matrix Background Effect */}
      <div className="matrix-bg"></div>

      {/* Navigation */}
      <nav className="navbar">
        <div className="nav-brand">
          <span className="bracket">[</span>
          <span className="brand-text">LANDON_CRAFT</span>
          <span className="bracket">]</span>
        </div>
        <div className="nav-links">
          <button onClick={() => setCurrentSection('home')} className={currentSection === 'home' ? 'active' : ''}>
            <span className="nav-icon">~/</span>home
          </button>
          <button onClick={() => setCurrentSection('about')} className={currentSection === 'about' ? 'active' : ''}>
            <span className="nav-icon">$</span>about
          </button>
          <button onClick={() => setCurrentSection('projects')} className={currentSection === 'projects' ? 'active' : ''}>
            <span className="nav-icon">#</span>projects
          </button>
          <button onClick={() => setCurrentSection('competitions')} className={currentSection === 'competitions' ? 'active' : ''}>
            <span className="nav-icon">%</span>competitions
          </button>
          <button onClick={() => setCurrentSection('contact')} className={currentSection === 'contact' ? 'active' : ''}>
            <span className="nav-icon">&gt;</span>contact
          </button>
        </div>
      </nav>

      {/* Hero Section */}
      {currentSection === 'home' && (
        <section className="hero">
          <div className="terminal-window">
            <div className="terminal-header">
              <span className="terminal-dot red"></span>
              <span className="terminal-dot yellow"></span>
              <span className="terminal-dot green"></span>
              <span className="terminal-title">dev_environment.sh</span>
            </div>
            <div className="terminal-body">
              <p className="terminal-line-typing">{terminalText}<span className="cursor">_</span></p>
              {showConnection && <p className="terminal-line success">✓ Backend services running</p>}
              {showEncryption && <p className="terminal-line"> &gt; UI deployed: production</p>}
              {showAuthentication && <p className="terminal-line success"> &gt; System status: Operational</p>}
            </div>
          </div>

          <div className="hero-content">
            <h1 className="glitch-text" data-text="LANDON CRAFT">LANDON CRAFT</h1>
            <div className="subtitle">
              <span className="typing-text">Software Engineer</span>
            </div>
            <p className="hero-description">
              Full-stack developer who builds reliable, well-engineered software — from RESTful APIs and React frontends
              <br />
              to cloud-deployed systems. Security-aware by background, engineering-first by practice.
            </p>
            <div className="cta-buttons">
              <button className="btn-primary" onClick={() => setCurrentSection('projects')}>
                <span className="btn-icon">{'</>'}</span> View Projects
              </button>
              <button className="btn-secondary" onClick={() => setCurrentSection('contact')}>
                <span className="btn-icon">📧</span> Get In Touch
              </button>
              <a href="https://github.com/landothedeveloper" target="_blank" rel="noopener noreferrer" className="btn-secondary">
                <span className="btn-icon">💻</span> GitHub
              </a>
              <a href="https://www.linkedin.com/in/landon-craft/" target="_blank" rel="noopener noreferrer" className="btn-secondary">
                <span className="btn-icon">💼</span> LinkedIn
              </a>
              <a href={`https://drive.google.com/uc?export=download&id=${RESUME_FILE_ID}`} target="_blank" rel="noopener noreferrer" className="btn-primary">
                <span className="btn-icon">📄</span> Resume
              </a>
            </div>
          </div>

          <div className="scan-line"></div>
        </section>
      )}

      {/* About Section */}
      {currentSection === 'about' && (
        <section className="about">
          <div className="section-header">
            <h2><span className="prompt">$</span> cat about.txt</h2>
            <div className="header-line"></div>
          </div>

          <div className="about-grid">
            <div className="about-card">
              <h3>👨‍💻 Background</h3>
              <p>
                Full-stack developer with a passion for building clean, scalable software. I focus on the full
                lifecycle — designing APIs, building React frontends, and shipping to production. My background in
                security gives me an edge in writing software that's robust by design, not as an afterthought.
              </p>
            </div>

            <div className="about-card">
              <h3>🎯 Focus Areas</h3>
              <ul className="focus-list">
                <li>Full-Stack Web Development (MERN)</li>
                <li>RESTful API Design & Backend Systems</li>
                <li>Cloud Deployment & DevOps Basics</li>
                <li>Application Security & Secure Auth</li>
              </ul>
            </div>

            <div className="about-card full-width">
              <h3>🔧 Skills & Technologies</h3>
              <div className="skills-grid">
                {skills.map((skill, index) => (
                  <span key={index} className={`skill-tag ${index >= 12 ? 'skill-tag-secondary' : ''}`} style={{ animationDelay: `${index * 0.05}s` }}>
                    {skill}
                  </span>
                ))}
              </div>
            </div>

            <div className="about-card">
              <h3>📜 Certifications</h3>
              <ul className="cert-list">
                {certifications.map((cert, index) => (
                  <li key={index}>
                    <span className="cert-icon">▸</span>{' '}
                    <a href={cert.url} target="_blank" rel="noopener noreferrer">
                      {cert.name}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {/* Projects Section */}
      {currentSection === 'projects' && (
        <section className="projects">
          <div className="section-header">
            <h2><span className="prompt">#</span> ls -la ./projects</h2>
            <div className="header-line"></div>
          </div>

          <div className="projects-grid">
            {projects.map((project, index) => (
              <div key={index} className="project-card" style={{ animationDelay: `${index * 0.15}s` }}>
                <div className="project-header">
                  <h3>{project.title}</h3>
                  <span className={`status ${project.status.toLowerCase().replace(' ', '-')}`}>
                    {project.status}
                  </span>
                </div>
                <p className="project-description">{project.description}</p>
                <div className="project-tech">
                  {project.tech.map((tech, i) => (
                    <span key={i} className="tech-badge">{tech}</span>
                  ))}
                </div>
                <button className="project-link" onClick={() => setCurrentSection(project.title)}>
                  View Details <span className="arrow">→</span>
                </button>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Project Detail Page */}
      {currentSection !== 'home' && currentSection !== 'about' && currentSection !== 'projects' && currentSection !== 'contact' && currentSection !== 'competitions' && (
        <section className="project-detail">
          <button className="back-button" onClick={() => setCurrentSection('projects')}>
            <span className="arrow">←</span> Back to Projects
          </button>

          {(() => {
            const project = projects.find(p => p.title === currentSection);
            if (!project) return null;

            return (
              <>
                <div className="detail-header">
                  <div>
                    <h1 className="detail-title">{project.title}</h1>
                    <p className="detail-subtitle">{project.description}</p>
                  </div>
                  <span className={`status ${project.status.toLowerCase().replace(' ', '-')}`}>
                    {project.status}
                  </span>
                </div>

                {/* Tech Stack */}
                <div className="detail-tech-stack">
                  <h3>🔧 Tech Stack</h3>
                  <div className="project-tech">
                    {project.tech.map((tech, i) => (
                      <span key={i} className="tech-badge">{tech}</span>
                    ))}
                  </div>
                </div>

                <div className="detail-content">
                  {/* Overview */}
                  <div className="detail-section">
                    <h2><span className="prompt">$</span> Overview</h2>
                    <div className="detail-card">
                      <p>{project.overview}</p>
                    </div>
                  </div>

                  {/* Features */}
                  <div className="detail-section">
                    <h2><span className="prompt">✦</span> Features</h2>
                    <div className="detail-card">
                      <ul className="detail-list">
                        {project.features.map((feature, i) => (
                          <li key={i}>{feature}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Architecture */}
                  <div className="detail-section">
                    <h2><span className="prompt">🏗️</span> Architecture</h2>
                    <div className="architecture-grid">
                      {project.architecture.map((layer, i) => (
                        <div key={i} className="architecture-layer">
                          <h4>{layer.layer}</h4>
                          <ul>
                            {layer.components.map((comp, j) => (
                              <li key={j}>{comp}</li>
                            ))}
                          </ul>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Technical Deep Dive */}
                  <div className="detail-section">
                    <h2><span className="prompt">🔍</span> Technical Deep Dive</h2>
                    <div className="deep-dive-card">
                      <h3>{project.technicalDeepDive.title}</h3>

                      <div className="deep-dive-section">
                        <h4 className="problem-heading">❌ The Problem</h4>
                        <p>{project.technicalDeepDive.problem}</p>
                      </div>

                      <div className="deep-dive-section">
                        <h4 className="solution-heading">✅ The Solution</h4>
                        <p>{project.technicalDeepDive.solution}</p>
                        <ul className="implementation-list">
                          {project.technicalDeepDive.implementation.map((item, i) => (
                            <li key={i}>{item}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="impact-box">
                        <strong>Impact:</strong> {project.technicalDeepDive.impact}
                      </div>
                    </div>
                  </div>

                  {/* Objectives */}
                  <div className="detail-section">
                    <h2><span className="prompt">#</span> Objectives</h2>
                    <div className="detail-card">
                      <ul className="detail-list">
                        {project.objectives.map((obj, i) => (
                          <li key={i}>{obj}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Methodology */}
                  <div className="detail-section">
                    <h2><span className="prompt">&gt;</span> Methodology</h2>
                    <div className="detail-card">
                      <ol className="detail-list numbered">
                        {project.methodology.map((method, i) => (
                          <li key={i}>{method}</li>
                        ))}
                      </ol>
                    </div>
                  </div>

                  {/* Code Snippets */}
                  <div className="detail-section">
                    <h2><span className="prompt">💻</span> Code Examples</h2>
                    {Object.entries(project.codeSnippets).map(([key, code], i) => (
                      <div key={i} className="code-snippet-box">
                        <h4>{key.replace(/([A-Z])/g, ' $1').trim()}</h4>
                        <pre><code>{code}</code></pre>
                      </div>
                    ))}
                  </div>

                  {/* Key Findings */}
                  <div className="detail-section">
                    <h2><span className="prompt">!</span> Key Findings</h2>
                    <div className="detail-card findings">
                      <ul className="detail-list findings-list">
                        {project.findings.map((finding, i) => (
                          <li key={i}><span className="finding-bullet">▸</span>{finding}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  {/* Impact */}
                  <div className="detail-section">
                    <h2><span className="prompt">✓</span> Impact</h2>
                    <div className="detail-card impact">
                      <p className="impact-text">{project.impact}</p>
                    </div>
                  </div>

                  {/* Security Details — Collapsible */}
                  <div className="detail-section">
                    <button
                      className="security-toggle"
                      onClick={() => toggleSecurityExpanded(project.id)}
                    >
                      <span className="security-toggle-icon">🔒</span>
                      Security Implementation Details
                      <span className="toggle-arrow">{expandedSecurity[project.id] ? '▲' : '▼'}</span>
                    </button>

                    {expandedSecurity[project.id] && (
                      <div className="security-section-collapsed">
                        <p className="security-intro">
                          This project incorporates security best practices as part of standard engineering — not as a separate layer.
                        </p>
                        <div className="threat-table">
                          <table>
                            <thead>
                              <tr>
                                <th>Concern</th>
                                <th>Risk</th>
                                <th>Mitigation Applied</th>
                              </tr>
                            </thead>
                            <tbody>
                              {project.securityDetails.items.map((item, i) => (
                                <tr key={i}>
                                  <td className="threat-name">{item.threat}</td>
                                  <td>
                                    <span className={`risk-badge risk-${item.risk.toLowerCase()}`}>
                                      {item.risk}
                                    </span>
                                  </td>
                                  <td className="mitigation-desc">{item.mitigation}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Links */}
                  {(project.github || project.demo) && (
                    <div className="detail-links">
                      {project.github && (
                        <a href={project.github} target="_blank" rel="noopener noreferrer" className="btn-primary">
                          <span className="btn-icon">💻</span> View on GitHub
                        </a>
                      )}
                      {project.demo && (
                        <a href={project.demo} target="_blank" rel="noopener noreferrer" className="btn-secondary">
                          <span className="btn-icon">🚀</span> Live Demo
                        </a>
                      )}
                      <div className="button-container-right">
                        <button className="btn-secondary" onClick={() => setCurrentSection('projects')}>
                          <span className="arrow">←</span> Back to Projects
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </>
            );
          })()}
        </section>
      )}

      {/* Competitions Section */}
      {currentSection === 'competitions' && (
        <section className="competitions">
          <div className="section-header">
            <h2><span className="prompt">%</span> ls -la ./competitions</h2>
            <div className="header-line"></div>
          </div>

          <div className="competitions-grid">
            {competitions.map((comp, index) => (
              <div key={index} className="competition-card" style={{ animationDelay: `${index * 0.15}s` }}>
                <div className="competition-header">
                  <div>
                    <h3>{comp.name}</h3>
                    <p className="competition-meta">
                      <span className="year-badge">{comp.year}</span>
                      <span className="type-badge">{comp.type}</span>
                      <span className="format-badge">{comp.format}</span>
                    </p>
                  </div>
                </div>

                <p className="competition-description">{comp.description}</p>

                <div className="competition-details">
                  <div className="detail-block">
                    <h4>🎯 Key Challenges</h4>
                    <ul>
                      {comp.challenges.map((challenge, i) => (
                        <li key={i}>{challenge}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="detail-block">
                    <h4>🔧 Skills Demonstrated</h4>
                    <div className="skills-grid">
                      {comp.skills.map((skill, i) => (
                        <span key={i} className="skill-tag">{skill}</span>
                      ))}
                    </div>
                  </div>

                  <div className="detail-block">
                    <h4>💡 Key Takeaways</h4>
                    <ul>
                      {comp.keyTakeaways.map((takeaway, i) => (
                        <li key={i}>{takeaway}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Contact Section */}
      {currentSection === 'contact' && (
        <section className="contact">
          <div className="section-header">
            <h2><span className="prompt">&gt;</span> ./connect.sh</h2>
            <div className="header-line"></div>
          </div>

          <div className="contact-content">
            <div className="contact-info">
              <h3>Let's Connect</h3>
              <p>Open to new grad SWE roles, internships, and collaborations. Let's build something together.</p>

              <div className="contact-methods">
                <a href="mailto:landoncraftbiz@gmail.com" className="contact-method">
                  <span className="contact-icon">📧</span>
                  <div>
                    <h4>Email</h4>
                    <p>landoncraftbiz@gmail.com</p>
                  </div>
                </a>

                <a href="https://www.linkedin.com/in/landon-craft/" target="_blank" rel="noopener noreferrer" className="contact-method">
                  <span className="contact-icon">💼</span>
                  <div>
                    <h4>LinkedIn</h4>
                    <p>linkedin.com/in/landon-craft</p>
                  </div>
                </a>

                <a href="https://github.com/landothedeveloper" target="_blank" rel="noopener noreferrer" className="contact-method">
                  <span className="contact-icon">💻</span>
                  <div>
                    <h4>GitHub</h4>
                    <p>github.com/landothedeveloper</p>
                  </div>
                </a>
              </div>
            </div>

            <div className="terminal-contact">
              <div className="terminal-header">
                <span className="terminal-dot red"></span>
                <span className="terminal-dot yellow"></span>
                <span className="terminal-dot green"></span>
                <span className="terminal-title">status.sh</span>
              </div>
              <div className="terminal-body">
                <p className="terminal-line success">✓ Available for opportunities</p>
                <p className="terminal-line"> &gt; Role: New Grad SWE / Full-Stack</p>
                <p className="terminal-line"> &gt; Location: Open to remote, Orlando, or relocation</p>
                <p className="terminal-line"> &gt; Stack: MERN, Python, REST APIs</p>
                <p className="terminal-line success"> &gt; Response time: &lt; 24hrs</p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="footer">
        <p>© 2026 Landon Craft | Software Engineering Portfolio</p>
        <p className="footer-hash">Built with React · Deployed with intent</p>
      </footer>
    </div>
  );
}

export default App;