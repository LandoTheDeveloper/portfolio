import './index.css';
import Nav from './components/Nav';
import Hero from './components/Hero';
import About from './components/About';
import Research from './components/Research';
import Projects from './components/Projects';
import Skills from './components/Skills';
import Contact from './components/Contact';
import { personal } from './data';

const Divider = () => (
  <hr style={{ border: 'none', borderTop: '0.5px solid var(--rule)', maxWidth: 720, margin: '0 auto' }} />
);

export default function App() {
  return (
    <>
      <Nav />
      <main>
        <Hero />
        <Divider />
        <About />
        <Divider />
        <Research />
        <Divider />
        <Projects />
        <Divider />
        <Skills />
        <Divider />
        <Contact />
      </main>
      <footer style={{
        textAlign: 'center',
        padding: '32px',
        fontFamily: 'var(--mono)',
        fontSize: '11px',
        color: 'var(--ink3)',
        letterSpacing: '0.04em',
        borderTop: '0.5px solid var(--rule)',
      }}>
        © {new Date().getFullYear()} {personal.name} · Built with React
      </footer>
    </>
  );
}
