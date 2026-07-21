import { research } from '../data';
import styles from './Research.module.css';

export default function Research() {
  return (
    <section className={styles.section} id="research">
      <p className={styles.label}>// {research.heading}</p>
      <h2 className={styles.h2}>What I'm working toward</h2>
      <p className={styles.body}>{research.intro}</p>

      <div className={styles.areas}>
        {research.areas.map((area) => (
          <div key={area.title} className={styles.area}>
            <h3 className={styles.areaTitle}>{area.title}</h3>
            <p className={styles.areaDesc}>{area.description}</p>
          </div>
        ))}
      </div>

      {research.note && <p className={styles.note}>{research.note}</p>}
    </section>
  );
}