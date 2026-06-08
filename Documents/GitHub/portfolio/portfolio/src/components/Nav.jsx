import { personal } from '../data';
import styles from './Nav.module.css';

export default function Nav() {
  return (
    <nav className={styles.nav}>
      <span className={styles.name}>{personal.name}</span>
      <div className={styles.links}>
        <a href="#about">About</a>
        <a href="#projects">Projects</a>
        <a href="#skills">Skills</a>
        <a href="#contact">Contact</a>
      </div>
      <a href={personal.resumeUrl} className={styles.cta} download>
        Resume ↓
      </a>
    </nav>
  );
}
