import { useState } from "react";
import styles from "./ProjectCarousel.module.css";

export default function ProjectCarousel({ images = [], title }) {
  const [index, setIndex] = useState(0);
  const [expanded, setExpanded] = useState(false);

  if (!images?.length) return null;

  return (
    <>
      <div className={styles.carousel}>
        <img
          src={images[index]}
          alt={`${title} screenshot`}
          className={styles.image}
          onClick={() => setExpanded(true)}
        />

        {images.length > 1 && (
          <>
            <button
              onClick={() =>
                setIndex((prev) => (prev - 1 + images.length) % images.length)
              }
              className={styles.arrow}
            >
              ‹
            </button>

            <button
              onClick={() =>
                setIndex((prev) => (prev + 1) % images.length)
              }
              className={styles.arrow}
            >
              ›
            </button>
          </>
        )}
      </div>

      {expanded && (
        <div
          className={styles.modal}
          onClick={() => setExpanded(false)}
        >
          <img
            src={images[index]}
            alt={`${title} screenshot`}
            className={styles.modalImage}
            onClick={(e) => e.stopPropagation()}
          />
        </div>
      )}
    </>
  );
}