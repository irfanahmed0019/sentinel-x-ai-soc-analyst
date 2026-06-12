/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#111827",
        steel: "#475569",
        signal: "#0f766e",
        hazard: "#dc2626",
      },
    },
  },
  plugins: [],
};
