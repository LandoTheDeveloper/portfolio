export const personal = {
  name: "Landon Craft",
  tagline: "Securing what actually matters",
  taglineEmphasis: "actually",
  bio: "I hold a B.S. in Computer Science with a minor in Secure Computing and Networking from the University of Central Florida, and I've applied to the M.S. in Cybersecurity (Thesis Track) program at the University of North Florida, with the goal of continuing on to a Ph.D. and a career in academic security research.",
  bioExtra: "I'm starting a cloud/cybersecurity role at CSX focused on cyber resiliency, SIEM, and AI-driven security automation. My research interests center on quantum-resistant cryptography and cloud security.",
  availability: "Starting at CSX · Applying to UNF MS-CIS",
  email: "landoncraftbiz@gmail.com",
  github: "https://github.com/LandoTheDeveloper",
  linkedin: "https://linkedin.com/in/landon-craft",
  resumeUrl: "https://drive.google.com/file/d/1UtyzkKs8lXzBIp78AebrjbWB07bZ6oaO/view?usp=sharing",
};

export const about = {
  education: "B.S. Computer Science — University of Central Florida, 2026",
  gpa: "3.7 / 4.0",
  location: "Jacksonville, FL",
  status: "Starting at CSX · MS-CIS Applicant, UNF",
};

export const coreStack = [
   "Java", "C", "Python", "React", "TypeScript", "Node.js",  "PostgreSQL", "Docker", "AWS",
];

export const research = {
  heading: "RESEARCH INTERESTS",
  intro: "I'm pursuing a thesis-track MS at UNF aimed at a PhD and academic career in cybersecurity research.",
  areas: [
    {
      title: "Quantum-Resistant Cryptography",
      description: "Migration strategies for cryptographic infrastructure as post-quantum standards move from specification to deployment, including hybrid schemes and performance tradeoffs in constrained environments.",
    },
    {
      title: "IoT Security",
      description: "Securing resource-constrained and embedded devices against firmware, protocol, and network-level attacks as IoT deployments scale in critical infrastructure and industrial environments.",
    },
    {
      title: "AI-Augmented Security Operations",
      description: "Applying ML and automation to SIEM pipelines and incident response without expanding attack surface or eroding analyst judgment.",
    },
  ],
  note: "Currently in conversation with UNF faculty about thesis advising in these areas.",
}

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
