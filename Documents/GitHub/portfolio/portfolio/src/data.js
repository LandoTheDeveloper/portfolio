export const personal = {
  name: "Landon Craft",
  tagline: "Building things that actually work.",
  taglineEmphasis: "actually",
  bio: "Software engineer with a CS degree from University of Central Florida. I enjoy turning complex problems into clean, reliable systems, whether that's a web app, an API, or a data pipeline.",
  bioExtra: "I'm looking for full-stack or backend roles at companies where engineering quality is taken seriously.",
  availability: "AVAILABLE FOR FULL-TIME ROLES",
  email: "landoncraftbiz@gmail.com",
  github: "https://github.com/LandoTheDeveloper",
  linkedin: "https://linkedin.com/in/landon-craft",
  resumeUrl: "https://drive.google.com/file/d/1UtyzkKs8lXzBIp78AebrjbWB07bZ6oaO/view?usp=sharing",
};

export const about = {
  education: "B.S. Computer Science — University of Central Florida, 2026",
  gpa: "3.7 / 4.0",
  location: "Orlando, FL · Open to remote",
  status: "Actively interviewing",
};

export const coreStack = [
   "Java", "C", "Python", "React", "TypeScript", "Node.js",  "PostgreSQL", "Docker", "AWS",
];

export const projects = [
  {
    type: "SENIOR DESIGN",
    status: "completed",
    title: "Smart Stock - Grocery & Kitchen Manager",
    description:
      "A full-stack grocery management app that scans receipts via OCR to auto-populate pantry inventory and generates recipe ideas based on ingredients on hand. Includes a companion mobile app built with React Native.",
    tags: ["TypeScript", "React", "Node.js", "Express", "MongoDB", "React Native", "Vite", "GitHub"],
    images: [
      "/images/dashboard.png",
      "/images/login.png",
      "/images/meal_planner.png",
      "/images/recipes.png",
      "/images/scanner.png",
      "/images/shopping_list.png",
    ],
    liveUrl: "https://www.smart-stock.food",
    codeUrl: "https://github.com/LandoTheDeveloper/smart-stock",
  },
  {
    type: "FULL-STACK",
    status: "completed",
    title: "Dishcord - Food-focused Social Media",
    description:
      "A full-stack social media platform for food lovers featuring a recipe feed, follower system, and real-time chat. Built collaboratively with a team using the MERN stack.",
    tags: ["MongoDB", "Express", "React", "Node.js", "REST API"],
    images: null,
    liveUrl: "",
    codeUrl: "https://github.com/dipl04/Final-Project-POOSD",
  },
  {
    type: "FULL-STACK",
    status: "completed",
    title: "Contact Manager",
    description:
      "A multi-user contact management web app with authentication, full CRUD operations, and a PHP REST API backend. Built on a LAMP stack as part of a team project.",
    tags: ["JavaScript", "PHP", "MySQL", "HTML", "CSS", "Apache", "REST API"],
    images: null,
    liveUrl: "",
    codeUrl: "https://github.com/LandoTheDeveloper/COP4331-small-project",
  },
  {
    type: "SYSTEMS",
    status: "completed",
    title: "Concurrent Hash Table",
    description:
      "A thread-safe hash table implemented in C with a custom read/write lock enabling safe concurrent access from multiple threads. Demonstrates low-level systems programming and OS concepts.",
    tags: ["C", "pthreads", "Makefile", "Concurrent Programming"],
    images: null,
    liveUrl: "",
    codeUrl: "https://github.com/LandoTheDeveloper/ConcurrentHashTable",
  },
];

export const skills = [
  {
    category: "LANGUAGES",
    items: ["TypeScript / JavaScript", "Python", "Java", "SQL"],
  },
  {
    category: "FRONTEND",
    items: ["React", "Next.js", "Tailwind CSS", "HTML / CSS"],
  },
  {
    category: "BACKEND",
    items: ["Node.js / Express", "FastAPI", "REST & GraphQL"],
  },
  {
    category: "DATA & INFRA",
    items: ["PostgreSQL", "Docker"],
  },
];
