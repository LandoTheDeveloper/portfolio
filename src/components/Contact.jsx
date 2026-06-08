import { personal } from '../data';
import styles from './Contact.module.css';

export default function Contact() {
  return (
    <section className={styles.section} id="contact">
      <div className={styles.inner}>
        <h2 className={styles.h2}>Let's talk</h2>
        <p className={styles.body}>
          I'm actively looking for full-time roles. If you're hiring or just want
          to chat about engineering, my inbox is open.
        </p>
        <div className={styles.links}>
          <a href={`mailto:${personal.email}`} className={styles.link}>
            ✉ {personal.email}
          </a>
          <a href={personal.github} target="_blank" rel="noreferrer" className={styles.link}>
            ⌥ GitHub
          </a>
          <a href={personal.linkedin} target="_blank" rel="noreferrer" className={styles.link}>
            in LinkedIn
          </a>
        </div>
      </div>
    </section>
  );
}
