export const personal = {
  name: "Landon Craft",
  tagline: "Building reliable cloud systems",
  taglineEmphasis: "reliable",
  bio: "I hold a B.S. in Computer Science with a minor in Secure Computing and Networking from the University of Central Florida, and I'm applying to Georgia Tech's online M.S. in Computer Science, with the goal of continuing on to a Ph.D. and a career as a professor and researcher.",
  bioExtra: "I work in Cloud Platform Services at CSX, where I build Azure infrastructure and automation with Terraform and Ansible. My research interests center on cloud infrastructure and AI.",
  availability: "Working at CSX",
  email: "landoncraftbiz@gmail.com",
  github: "https://github.com/LandoTheDeveloper",
  linkedin: "https://linkedin.com/in/landon-craft",
  resumeUrl: "https://drive.google.com/file/d/1xWH1SrGSqRzV332qc_-HRpFmuBjgXfRu/view?usp=sharing",
};

export const about = {
  education: "B.S. Computer Science, University of Central Florida, 2026",
  gpa: "3.7 / 4.0",
  location: "Jacksonville, FL",
  status: "Working at CSX",
};

export const coreStack = [
  "Python", "C", "Java", "TypeScript", "React", "Node.js",
  "Azure", "Terraform", "Ansible", "Docker", "PostgreSQL", "AWS",
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
];

export const skills = [
  {
    category: "LANGUAGES",
    items: ["Python", "C", "Java", "TypeScript / JavaScript", "SQL"],
  },
  {
    category: "CLOUD & INFRA",
    items: ["Azure", "Terraform", "Ansible Automation Platform", "Docker"],
  },
  {
    category: "AI & AUTOMATION",
    items: ["OpenAI APIs", "Google Gemini", "Power Automate"],
  },
  {
    category: "WEB & DATA",
    items: ["React", "Next.js", "Node.js / Express", "FastAPI", "REST & GraphQL", "PostgreSQL", "Tailwind CSS"],
  },
];