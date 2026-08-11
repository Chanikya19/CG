/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // High-end premium dark & cybersecurity themed color palette
        cyber: {
          dark: '#030712',
          card: '#0f172a',
          border: '#1e293b',
          glow: '#10b981', // Emerald green representing safety/encryption
          accent: '#3b82f6', // Cyber blue
          alert: '#ef4444', // Alert red
        }
      }
    },
  },
  plugins: [],
}
