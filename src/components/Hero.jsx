import { personal, coreStack } from '../data';
import styles from './Hero.module.css';
import headshot from '../assets/headshot.png'

export default function Hero() {
  // Split tagline around the emphasis word so we can italicize it
  const { tagline, taglineEmphasis } = personal;
  const parts = tagline.split(taglineEmphasis);

  return (
  <section className={styles.hero}>
    <div className={styles.heroGrid}>
      <img
        src={headshot}
        alt="Landon Craft headshot"
        className={styles.headshot}
      />

      <div className={styles.content}>
        <p className={styles.eyebrow}>// {personal.availability}</p>

        <h1 className={styles.h1}>
          {parts[0]}
          <em className={styles.em}>{taglineEmphasis}</em>
          {parts[1]}
        </h1>

        <p className={styles.sub}>{personal.bio}</p>

        <div className={styles.actions}>
          <a href="#projects" className={styles.btnPrimary}>View Projects</a>
          <a href="#contact" className={styles.btnGhost}>Get in Touch</a>
        </div>
      </div>
    </div>

    <div className={styles.stack}>
      <p className={styles.stackLabel}>// CORE STACK</p>
      <div className={styles.pills}>
        {coreStack.map((tech) => (
          <span key={tech} className={styles.pill}>{tech}</span>
        ))}
      </div>
    </div>
  </section>
);
}
