import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [terminalText, setTerminalText] = useState('');
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
      }
    }, 50);
    
    return () => clearInterval(timer);
  }, []);

  const projects = [
    {
      title: 'Smart Stock',
      description: 'Full-stack food tracking app implementing industry-standard security practices: bcrypt password hashing with salt, JWT token-based authentication, and secure API design to prevent common web vulnerabilities.',
      tech: ['JWT', 'bcrypt', 'Node.js', 'React', 'SQL'],
      status: 'In Progress'
    },
    {
      title: 'Password Strength Analysis Chrome Extension',
      description: 'Browser extension that evaluates password entropy and checks against known breach databases. Implements NIST password guidelines and provides real-time feedback on password security.',
      tech: ['JavaScript', 'Chrome Extension API', 'Security Best Practices'],
      status: 'Completed'
    }
  ];

  const skills = [
    'Network Security', 'Penetration Testing', 'SIEM', 'Incident Response',
    'Python', 'Linux', 'Wireshark', 'Metasploit', 'Nmap', 'Burp Suite',
    'Cloud Security', 'Threat Intelligence', 'Security Auditing'
  ];

  const certifications = [
    'CompTIA A+',
    'CompTIA Network+',
    'CompTIA Security+ (In Progress)'

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
              <p className="terminal-line">{terminalText}<span className="cursor">_</span></p>
              <p className="terminal-line success">✓ Connection established</p>
              <p className="terminal-line">✓ Encryption: AES-256</p>
              <p className="terminal-line">✓ Authentication: Multi-factor</p>
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
                    <span className="cert-icon">▸</span> {cert}
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
                <button className="project-link">
                  View Details <span className="arrow">→</span>
                </button>
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