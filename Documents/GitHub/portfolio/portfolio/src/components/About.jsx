import { personal, about } from '../data';
import styles from './About.module.css';

const facts = [
  { label: 'EDUCATION', value: about.education },
  { label: 'GPA',       value: about.gpa },
  { label: 'LOCATION',  value: about.location },
  { label: 'STATUS',    value: about.status, green: true },
];

export default function About() {
  return (
    <section className={styles.section} id="about">
      <p className={styles.label}>// ABOUT</p>
      <div className={styles.grid}>
        <div>
          <h2 className={styles.h2}>A bit about me</h2>
          <p className={styles.body}>{personal.bio}</p>
          {personal.bioExtra && (
            <p className={styles.body} style={{ marginTop: 12 }}>{personal.bioExtra}</p>
          )}
        </div>
        <div className={styles.facts}>
          {facts.map((f) => (
            <div key={f.label} className={styles.fact}>
              <div className={styles.factLabel}>{f.label}</div>
              <div className={`${styles.factVal} ${f.green ? styles.green : ''}`}>{f.value}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
