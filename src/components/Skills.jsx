import { skills } from '../data';
import styles from './Skills.module.css';

export default function Skills() {
  return (
    <section className={styles.section} id="skills">
      <p className={styles.label}>// SKILLS</p>
      <h2 className={styles.h2}>What I work with</h2>
      <div className={styles.grid}>
        {skills.map((group) => (
          <div key={group.category} className={styles.group}>
            <p className={styles.groupTitle}>{group.category}</p>
            <ul className={styles.list}>
              {group.items.map((item) => (
                <li key={item} className={styles.item}>{item}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}
