/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",       // project-level templates
    "./**/templates/**/*.html",    // app-level templates (accounts, petitions, etc.)
    "./static/src/**/*.js",        // if you write JS that uses Tailwind classes
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
