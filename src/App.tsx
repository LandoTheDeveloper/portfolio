import { useState, useEffect } from 'react';
import './App.css';

const RESUME_FILE_ID = "1L6PMjM96zToZFfvoyXoxV2D9AKHfxP0v";

/* ───────────────────────────────
   TYPES
─────────────────────────────── */

type Section =
  | 'home'
  | 'about'
  | 'projects'
  | 'competitions'
  | 'contact';

type Project = (typeof projects)[number];

/* ───────────────────────────────
   DATA
─────────────────────────────── */

const projects = [
  {
    id: 1,
    title: 'Smart Stock',
    subtitle: 'Secure Food Inventory Management',
    description: 'Full-stack MERN application with enterprise-grade security...',
    tech: ['MongoDB', 'Express.js', 'React', 'Node.js', 'OAuth 2.0', 'JWT', 'bcrypt', 'DigitalOcean'],
    status: 'In Progress',
    github: 'https://github.com/landothedeveloper/smart-stock',
    demo: 'https://smart-stock.food',
    overview: 'Production-ready food inventory management system...',
    securityImpact: 'Multi-layered security architecture...',
    highlights: [
      { label: 'Users', value: '200+', note: 'zero security incidents' },
      { label: 'OAuth adoption', value: '67%', note: 'chose Google login over passwords' },
      { label: 'SSL Labs', value: 'A+', note: 'all traffic encrypted' },
    ],
    threatModel: [
      { threat: 'Account Takeover', risk: 'CRITICAL', mitigation: 'OOB email verification...', status: 'Mitigated' },
      { threat: 'Credential Stuffing', risk: 'HIGH', mitigation: 'bcrypt + rate limiting', status: 'Mitigated' },
      { threat: 'Man-in-the-Middle', risk: 'HIGH', mitigation: 'HTTPS/TLS + HSTS', status: 'Mitigated' },
    ],
    deepDive: {
      title: 'Why out-of-band email verification?',
      problem: 'Sessions can be hijacked...',
      solution: 'Email-based verification independent of session.',
      points: [
        'Single-use tokens',
        'Session invalidation',
        'Email-gated auth',
      ]
    },
    code: `// example code`
  },
  {
    id: 2,
    title: 'ShieldCheck',
    subtitle: 'Password Strength Heuristics',
    description: 'Chrome extension...',
    tech: ['JavaScript', 'Chrome API', 'RegExp'],
    status: 'Completed',
    github: 'https://github.com/LandoTheDeveloper/PasswordStrengthChecker',
    overview: 'Password analysis tool...',
    securityImpact: 'Prevents weak credential usage...',
    highlights: [
      { label: 'Weak passwords', value: '−85%', note: 'testing' },
      { label: 'Data sent', value: '0 bytes', note: 'local only' },
      { label: 'Attack surface', value: 'None', note: 'no APIs' },
    ],
    threatModel: [
      { threat: 'Dictionary Attack', risk: 'HIGH', mitigation: 'Blacklist', status: 'Mitigated' },
    ],
    deepDive: {
      title: 'Entropy vs Complexity',
      problem: 'Users misunderstand password strength',
      solution: 'Length-weighted scoring system',
      points: [
        'Length matters most',
        'Character diversity scoring',
        'Blacklist common passwords',
      ]
    },
    code: `function checkPasswordStrength(password) {}`
  }
] as const;

/* ───────────────────────────────
   OTHER DATA
─────────────────────────────── */

const competitions = [/* unchanged */];
const skills = { /* unchanged */ };
const certifications = [/* unchanged */];

/* ───────────────────────────────
   APP
─────────────────────────────── */

export default function App() {
  const [section, setSection] = useState<Section>('home');
  const [activeProject, setActiveProject] = useState<Project | null>(null);
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
  ] as const;

  return (
    <div className={`app ${loaded ? 'loaded' : ''}`}>
      <div className="grain" />

      <nav className="nav">
        <button
          className="nav-logo"
          onClick={() => {
            setSection('home');
            setActiveProject(null);
          }}
        >
          LC
        </button>

        <div className={`nav-links ${menuOpen ? 'open' : ''}`}>
          {nav.map(n => (
            <button
              key={n.id}
              className={`nav-link ${section === n.id && !activeProject ? 'active' : ''}`}
              onClick={() => {
                setSection(n.id);
                setActiveProject(null);
              }}
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
        {section === 'projects' && !activeProject && (
          <Projects setActiveProject={setActiveProject} />
        )}
        {section === 'competitions' && !activeProject && <Competitions />}
        {section === 'contact' && !activeProject && <Contact />}
        {activeProject && (
          <ProjectDetail
            project={activeProject}
            back={() => setActiveProject(null)}
          />
        )}
      </main>

      <footer className="footer">
        <span>© 2026 Landon Craft</span>
        <span className="footer-mono">SHA-256: d4f8c9b2…</span>
      </footer>
    </div>
  );
}

/* ───────────────────────────────
   COMPONENT PROPS (FIXED)
─────────────────────────────── */

function Home({ setSection }: { setSection: (s: Section) => void }) {
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
      <h1 className="home-name">Landon<br />Craft</h1>
      <p className={`home-role ${fade ? 'fade-in' : 'fade-out'}`}>
        {roles[roleIdx]}
      </p>

      <button className="btn-primary" onClick={() => setSection('projects')}>
        View Projects
      </button>
    </section>
  );
}

function Projects({
  setActiveProject,
}: {
  setActiveProject: (p: Project) => void;
}) {
  return (
    <section className="projects page-section">
      {projects.map((p, i) => (
        <div key={p.id} onClick={() => setActiveProject(p)}>
          {p.title}
        </div>
      ))}
    </section>
  );
}

function ProjectDetail({
  project: p,
  back,
}: {
  project: Project;
  back: () => void;
}) {
  return (
    <section className="project-detail page-section">
      <button onClick={back}>← Back</button>
      <h2>{p.title}</h2>
      <p>{p.overview}</p>
    </section>
  );
}

/* ───────────────────────────────
   PLACEHOLDERS (UNCHANGED)
─────────────────────────────── */

function About() {
  return <section className="about page-section">About</section>;
}

function Competitions() {
  return <section className="competitions page-section">Competitions</section>;
}

function Contact() {
  return <section className="contact page-section">Contact</section>;
}