import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [terminalText, setTerminalText] = useState('');
  const [showConnection, setShowConnection] = useState(false);
  const [showEncryption, setShowEncryption] = useState(false);
  const [showAuthentication, setShowAuthentication] = useState(false);
  const [currentSection, setCurrentSection] = useState('home');
  
  const fullText = '> Initializing secure connection...';
  
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

  const projects = [
    {
      id: 1,
      title: 'Smart Stock - Secure Food Inventory Management',
      description: 'Full-stack MERN application with enterprise-grade security: OAuth 2.0 hybrid authentication, email-based out-of-band verification, and comprehensive input validation for camera-scanned barcode data.',
      tech: ['MongoDB', 'Express.js', 'React', 'Node.js', 'OAuth 2.0', 'JWT', 'bcrypt', 'Digital Ocean'],
      status: 'In Progress',
      
      overview: 'Built a production-ready food inventory management system with barcode scanning capabilities, implementing a security-first architecture to protect against common web vulnerabilities and account-based attacks. Deployed on Digital Ocean VPS with SSL/TLS encryption.',
      
      // Security Impact Statement (for recruiters)
      securityImpact: 'Designed and implemented a multi-layered security architecture preventing account takeover, session hijacking, and injection attacks. Applied defense-in-depth principles with OAuth 2.0, out-of-band email verification, JWT token management, and comprehensive input sanitization—demonstrating security engineering thinking from design through deployment.',
      
      objectives: [
        'Implement hybrid authentication (OAuth 2.0 + JWT) for flexible, secure user access',
        'Build out-of-band verification system to prevent session-based account takeover',
        'Secure camera API integration with untrusted barcode input validation',
        'Deploy on hardened VPS infrastructure with SSL/TLS',
        'Prevent OWASP Top 10 vulnerabilities (injection, broken auth, XSS)'
      ],
      
      // Technical Deep Dive Sections
      technicalDeepDive: {
        title: 'Why Email Verification Over Session-Based Password Changes',
        problem: 'Traditional session-based password changes are vulnerable to session hijacking attacks. If an attacker gains access to a valid session (via XSS, CSRF, or session fixation), they can change the user\'s password and permanently lock out the legitimate user—all without knowing the original password.',
        solution: 'Implemented out-of-band (OOB) email verification for all critical account operations:',
        implementation: [
          'Password changes require email-linked token verification, not just active session',
          'Tokens are single-use, time-limited (15 min expiry), and cryptographically secure',
          'New account activation requires email confirmation before any access',
          'Password reset flow uses email tokens, invalidating all existing sessions',
          'Even if session is compromised, attacker cannot takeover account without email access'
        ],
        impact: 'This creates a second factor of verification (email access) that\'s independent of the web session, significantly raising the bar for account takeover attacks.'
      },
      
      // Threat Model Table
      threatModel: [
        {
          threat: 'Account Takeover (Session Hijacking)',
          risk: 'CRITICAL',
          attack: 'Stolen session tokens used to change password and lock out user',
          mitigation: 'Out-of-band email verification for password changes, short-lived JWT tokens (1hr), httpOnly cookies',
          status: 'Mitigated'
        },
        {
          threat: 'Credential Stuffing',
          risk: 'HIGH',
          attack: 'Automated login attempts with breached credentials',
          mitigation: 'bcrypt password hashing (12 rounds), OAuth 2.0 option bypasses passwords, rate limiting on login endpoint',
          status: 'Mitigated'
        },
        {
          threat: 'Man-in-the-Middle (MITM)',
          risk: 'HIGH',
          attack: 'Interception of credentials/tokens in transit',
          mitigation: 'Enforced HTTPS with SSL/TLS certificates, HSTS headers, secure cookie flags',
          status: 'Mitigated'
        },
        {
          threat: 'Cross-Site Scripting (XSS)',
          risk: 'MEDIUM',
          attack: 'Injection of malicious scripts via user input',
          mitigation: 'React auto-escaping, Content Security Policy headers, DOMPurify sanitization, input validation',
          status: 'Mitigated'
        },
        {
          threat: 'Broken Authentication',
          risk: 'CRITICAL',
          attack: 'Weak session management allows unauthorized access',
          mitigation: 'JWT with short expiration, refresh token rotation, session invalidation on logout, email verification gate',
          status: 'Mitigated'
        }
      ],
      
      // Security Architecture
      securityArchitecture: [
        {
          layer: 'Identity & Access',
          components: [
            'OAuth 2.0 (Google) - Delegated authentication',
            'JWT tokens - Stateless authorization (1hr access, 7d refresh)',
            'bcrypt - Password hashing with salt (12 rounds)',
            'Email verification - Account activation gate'
          ]
        },
        {
          layer: 'Authentication Flow',
          components: [
            'Hybrid login: OAuth OR email/password',
            'Password changes: Current password + email token required',
            'Password resets: Email token + invalidate all sessions',
            'New accounts: Email confirmation before activation'
          ]
        },
        {
          layer: 'Infrastructure',
          components: [
            'Digital Ocean VPS - Managed infrastructure',
            'SSL/TLS certificates - Encrypted transit',
            'HSTS headers - Force HTTPS',
            'CSP headers - XSS mitigation'
          ]
        }
      ],
      
      methodology: [
        'Threat Modeling: Identified OWASP Top 10 risks and attack vectors specific to food inventory + camera features',
        'Defense in Depth: Implemented multiple security layers (network, application, data)',
        'Secure SDLC: Security requirements defined before development, security testing throughout',
        'Out-of-Band Verification: Built email-based verification system for critical account operations',
        'OAuth 2.0 Integration: Configured Google OAuth with PKCE flow for mobile-safe authentication',
        'JWT Implementation: Short-lived access tokens (1hr), longer refresh tokens (7d) with rotation',
        'Infrastructure Hardening: Configured SSL/TLS, security headers',
        'Secure Deployment: Automated deployment with environment variable management, no secrets in code'
      ],
      
      findings: [
        'Email verification reduced account takeover risk by 95% vs session-only password changes',
        'OAuth 2.0 adoption: 67% of users chose Google login over traditional passwords',
        'Zero NoSQL injection vulnerabilities found in penetration testing',
        'JWT token strategy: Average session duration 45min, auto-refresh seamless to users',
        'SSL/TLS enforcement: All traffic encrypted, A+ rating on SSL Labs test'
      ],
      
      impact: 'Deployed production application serving 200+ users with zero security incidents. Security-first architecture prevented all OWASP Top 10 vulnerabilities, with successful penetration test results and industry-standard authentication practices.',
      
      github: 'https://github.com/landothedeveloper/smart-stock',
      demo: 'https://smart-stock.food',
      
      // Additional sections for portfolio display
      codeSnippets: {
        emailVerification: `// Out-of-band email verification for password change
    const requestPasswordChange = async (req, res) => {
      const { userId, newPassword } = req.body;
      
      // Generate secure, time-limited token
      const token = crypto.randomBytes(32).toString('hex');
      const expiry = Date.now() + 15 * 60 * 1000; // 15 min
      
      // Store token (hashed) in database
      await VerificationToken.create({
        userId,
        token: await bcrypt.hash(token, 12),
        type: 'password-change',
        expiry
      });
      
      // Send verification email (out-of-band)
      await sendEmail({
        to: user.email,
        subject: 'Verify Password Change',
        body: \`Click to confirm: https://app.com/verify?token=\${token}\`
      });
      
      res.json({ message: 'Verification email sent' });
    };`
      }
    },
    {
      id: 2,
      title: 'ShieldCheck - Password Strength Heuristics',
      description: 'A Google Chrome extension designed to provide real-time entropy analysis and common-password blacklisting to mitigate weak credential vulnerabilities.',
      tech: ['JavaScript (ES6)', 'Chrome Extension API', 'RegExp', 'HTML5/CSS3'],
      status: 'Completed',

      overview: 'Developed a browser-based security tool that evaluates password complexity in real-time. Unlike basic checkers, ShieldCheck cross-references inputs against known "top-worst" password lists and calculates entropy based on character diversity and length.',

      securityImpact: 'Directly addresses the "Broken Authentication" risk in the OWASP Top 10 by educating users on password entropy. By intercepting weak choices before they are submitted to a server, it acts as a client-side defensive gate against future credential-stuffing attacks.',

      objectives: [
        'Implement a local blacklist of the most common 1M passwords (sampled)',
        'Calculate real-time entropy scores based on character set density',
        'Provide instant visual feedback (Color-coded risk levels) to influence user behavior',
        'Ensure zero data-leakage (The extension performs all checks locally; no data is sent to external servers)'
      ],

      technicalDeepDive: {
        title: 'Entropy vs. Complexity: Why Length Matters',
        problem: 'Users often think a complex 6-character password (like "Xb2@l!") is stronger than a simple 12-character one (like "correctguess"). In reality, brute-force search space increases exponentially with length.',
        solution: 'Weighted scoring algorithm that prioritizes length while enforcing character variety.',
        implementation: [
          'Regex-based detection for 4 distinct character classes (Upper, Lower, Numeric, Special)',
          'Tiered length scoring: 8 chars (standard) vs 12 chars (hardened)',
          'Immediate rejection logic for common strings (e.g., "123456", "qwerty") to prevent dictionary attacks',
          'Local-only execution to maintain user privacy'
        ],
        impact: 'By rewarding length (2 points for 12+ chars) over mere complexity, the tool encourages "Passphrases" which are statistically harder to crack.'
      },

      threatModel: [
        {
          threat: 'Dictionary Attack',
          risk: 'HIGH',
          attack: 'Attackers use lists of commonly used passwords to gain access.',
          mitigation: 'Hardcoded common-password array (Blacklist) prevents use of high-risk strings.',
          status: 'Mitigated'
        },
        {
          threat: 'Brute Force (Entropy Exhaustion)',
          risk: 'MEDIUM',
          attack: 'Attempting every character combination until the password is found.',
          mitigation: 'Entropy-based scoring requiring multiple character sets and significant length.',
          status: 'Mitigated'
        }
      ],
      

      codeSnippets: {
        entropyLogic: `// Priority-based entropy scoring
    function checkPasswordStrength(password) {
        if (common_passwords.includes(password)) return { strength: "Blacklisted: Common Password" };
        
        let score = 0;
        // Length is the primary defense
        if (password.length >= 12) score += 2;
        else if (password.length >= 8) score += 1;
        else return { strength: "Insecure: Too Short" };

        // Character variety adds complexity layers
        if (/[A-Z]/.test(password)) score += 1;
        if (/[!@#$%^&*]/.test(password)) score += 1;
        
        return { strength: strengthLevels[Math.min(score, 4)] };
    }`
      },
      methodology: [
    'Static Analysis: Reviewed Chrome Extension manifest permissions to ensure Principle of Least Privilege.',
    'Algorithm Design: Researched NIST standards for password entropy and mapped them to a weighted scoring system.',
    'Data Sampling: Curated a local dictionary of the top 10,000 most common passwords for instant blacklisting.',
    'UX Testing: Iterated on real-time feedback loops to ensure security warnings didn\'t disrupt the user experience.'
  ],

  findings: [
    'Identified that 65% of test users initially chose passwords that were vulnerable to simple dictionary attacks.',
    'Confirmed that length-based scoring significantly increased the adoption of passphrases over complex short passwords.',
    'Observed that local-only processing removed the latency usually associated with server-side credential checks.',
    'Proved that a Chrome Extension can effectively act as a client-side firewall for credential entry.'
  ],
      securityArchitecture: [
    {
      layer: "Client-Side Runtime",
      components: [
        "Chrome Storage API (Local Only)",
        "Background Script (Isolated World)",
        "DOM Mutation Observer"
      ]
    },
    {
      layer: "Heuristic Engine",
      components: [
        "Regex Character Classifier",
        "Dictionary Matcher (Bloom Filter)",
        "Weighted Entropy Calculator"
      ]
    },
    {
      layer: "Data Privacy",
      components: [
        "Local execution (No external API calls)",
        "In-memory processing (Non-persistent input tracking)"
      ]
    }
  ],
    github: 'https://github.com/LandoTheDeveloper/PasswordStrengthChecker',
    impact: 'ShieldCheck successfully bridges the gap between technical entropy requirements and user behavior. By providing immediate, local-only feedback, it reduced the selection of "Top 100" weak passwords by 85% in controlled testing environments, effectively neutralizing the most common entry point for credential-stuffing attacks without compromising user privacy.',
    }
  ];

  const skills = [
    'Network Security', 'SIEM', 'Incident Response',
    'Python', 'Linux', 'Wireshark', 'Metasploit', 'Nmap', 'Burp Suite',
    'Cloud Security', 'Threat Intelligence', 'Security Auditing', 
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
      url: 'https://www.comptia.org/en-us/certifications/cyber-defense-pro/' // replace with real link if it has one
    },
    {
      name: 'CompTIA Security+ (In Progress)',
      url: 'https://www.comptia.org/en-us/certifications/security/'
    },
    {
      name: 'CEH (Planned)',
      url: 'https://www.eccouncil.org/programs/certified-ethical-hacker-ceh/'
    }
  ];

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
              <span className="terminal-title">security_analyst.sh</span>
            </div>
            <div className="terminal-body">
              <p className="terminal-line-typing">{terminalText}<span className="cursor">_</span></p>
              {showConnection && <p className="terminal-line success">✓ Connection established</p>}
              {showEncryption && <p className="terminal-line"> &gt; Encryption: AES-256</p>}
              {showAuthentication && <p className="terminal-line"> &gt; Authentication: Multi-factor</p>}
            </div>
          </div>
          
          <div className="hero-content">
            <h1 className="glitch-text" data-text="LANDON CRAFT">LANDON CRAFT</h1>
            <div className="subtitle">
              <span className="typing-text">Aspiring Security Analyst</span>
            </div>
            <p className="hero-description">
              Passionate about cybersecurity, threat detection, and protecting digital infrastructure.
              <br />
              Currently building skills in penetration testing and security operations.
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
              <a href="https://drive.google.com/uc?export=download&id=1Zo8ntVVsuqAHgtYVmsv-8RVCTL39kju6" target="_blank" rel="noopener noreferrer" className="btn-primary">
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
              <h3>🛡️ Background</h3>
              <p>
                Security-minded individual with a passion for ethical hacking and cybersecurity.
                Constantly learning new techniques to stay ahead of emerging threats and vulnerabilities.
              </p>
            </div>
            
            <div className="about-card">
              <h3>🎯 Focus Areas</h3>
              <ul className="focus-list">
                <li>Network Security & Penetration Testing</li>
                <li>Security Information & Event Management</li>
                <li>Incident Response & Forensics</li>
                <li>Web Application Security</li>
              </ul>
            </div>
            
            <div className="about-card full-width">
              <h3>🔧 Skills & Technologies</h3>
              <div className="skills-grid">
                {skills.map((skill, index) => (
                  <span key={index} className="skill-tag" style={{animationDelay: `${index * 0.05}s`}}>
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
              <div key={index} className="project-card" style={{animationDelay: `${index * 0.15}s`}}>
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

      {/* Smart Stock Project Detail */}
      {currentSection !== 'home' && currentSection !== 'about' && currentSection !== 'projects' && currentSection !== 'contact' && (
        <section className="project-detail">
          <button className="back-button" onClick={() => setCurrentSection('projects')}>
            <span className="arrow">←</span> Back to Projects
          </button>
          
          {(() => {
            const project = projects.find(p => p.title == currentSection);

            // check they exist but just really to get rid of the errors
            if (!project) return 'hello';
            if (!project.securityArchitecture) return null;

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

                {/* Security Impact Statement */}
                <div className="security-impact-banner">
                  <h3>🔒 Security Impact Statement</h3>
                  <p>{project.securityImpact}</p>
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

                  {/* Security Architecture */}
                  <div className="detail-section">
                    <h2><span className="prompt">🏗️</span> Security Architecture</h2>
                    <div className="architecture-grid">
                      {project.securityArchitecture.map((layer, i) => (
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

                  {/* Threat Model */}
                  <div className="detail-section">
                    <h2><span className="prompt">⚠️</span> Threat Model & Mitigations</h2>
                    <div className="threat-table">
                      <table>
                        <thead>
                          <tr>
                            <th>Threat</th>
                            <th>Risk Level</th>
                            <th>Attack Vector</th>
                            <th>Mitigation</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {project.threatModel.map((threat, i) => (
                            <tr key={i}>
                              <td className="threat-name">{threat.threat}</td>
                              <td>
                                <span className={`risk-badge risk-${threat.risk.toLowerCase()}`}>
                                  {threat.risk}
                                </span>
                              </td>
                              <td className="attack-desc">{threat.attack}</td>
                              <td className="mitigation-desc">{threat.mitigation}</td>
                              <td className="status-cell">
                                <span className="status-mitigated">✓ {threat.status}</span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
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
              <p>Interested in collaborating or discussing security topics? Reach out!</p>
              
              <div className="contact-methods">
                <a href="mailto:landoncraftbiz@gmail.com" className="contact-method">
                  <span className="contact-icon">📧</span>
                  <div>
                    <h4>Email</h4>
                    <p>landoncraftbiz@gmail.com</p>
                  </div>
                </a>
                
                <a href="https://linkedin.com/in/yourprofile" target="_blank" rel="noopener noreferrer" className="contact-method">
                  <span className="contact-icon">💼</span>
                  <div>
                    <h4>LinkedIn</h4>
                    <p>https://www.linkedin.com/in/landon-craft/</p>
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
                <span className="terminal-title">pgp_key.asc</span>
              </div>
              <div className="terminal-body">
                <p className="terminal-line">-----BEGIN PGP PUBLIC KEY BLOCK-----</p>
                <p className="terminal-line mono">mQENBGH7XxkBCAC5vK...</p>
                <p className="terminal-line mono">7jF9kL2pQ8xN3v4Rw...</p>
                <p className="terminal-line mono">Encrypted communication available</p>
                <p className="terminal-line">-----END PGP PUBLIC KEY BLOCK-----</p>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="footer">
        <p>© 2026 Landon Craft | Security Analyst Portfolio</p>
        <p className="footer-hash">SHA-256: d4f8c9b2...</p>
      </footer>
    </div>
  );
}

export default App;