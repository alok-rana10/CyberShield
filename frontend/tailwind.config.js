/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070a0f',
          900: '#0c121d',
          800: '#141d2e',
          700: '#1d2a42',
          600: '#2b3d5e',
          accent: '#06b6d4',
          glow: '#0891b2',
        },
      },
    },
  },
  plugins: [],
}
