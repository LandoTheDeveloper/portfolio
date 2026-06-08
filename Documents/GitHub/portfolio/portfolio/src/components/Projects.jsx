import { projects } from '../data';
import styles from './Projects.module.css';
import ProjectCarousel from './ProjectCarousel';

export default function Projects() {
  return (
    <section className={styles.section} id="projects">
      <p className={styles.label}>// SELECTED PROJECTS</p>
      <h2 className={styles.h2}>What I've built</h2>
      <div className={styles.list}>
        {projects.map((p) => (
          <div key={p.title} className={styles.proj}>
            <div className={styles.info}>
              <div className={styles.meta}>
                <span className={styles.type}>{p.type}</span>
                <span className={styles.dot} />
                <span className={styles.status}>{p.status}</span>
              </div>
              <h3 className={styles.projTitle}>{p.title}</h3>
              <p className={styles.desc}>{p.description}</p>
              <div className={styles.tags}>
                {p.tags.map((t) => (
                  <span key={t} className={styles.tag}>{t}</span>
                ))}
              </div>
              <ProjectCarousel
                images={p.images}
                title={p.title}
              />
            </div>
            <div className={styles.links}>
              {p.liveUrl && (
                <a href={p.liveUrl} target="_blank" rel="noreferrer" className={styles.link}>
                  ↗ Live
                </a>
              )}
              {p.codeUrl && (
                <a href={p.codeUrl} target="_blank" rel="noreferrer" className={styles.link}>
                  ⌥ Code
                </a>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
