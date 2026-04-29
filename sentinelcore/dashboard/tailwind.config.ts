import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        threat: {
          clean: "#22c55e",
          suspicious: "#f59e0b",
          malicious: "#ef4444",
          unknown: "#6b7280",
        },
      },
    },
  },
  plugins: [],
};

export default config;
