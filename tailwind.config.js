/**
 * Tailwind config for the panel UI.
 *
 * Built with the standalone CLI (no Node needed) via scripts/build_css.sh into
 * public/assets/app.css. `content` must list every place class names appear so
 * the purge keeps them; anything built by string concatenation goes in safelist.
 */
module.exports = {
  darkMode: 'class',
  content: [
    './templates/**/*.twig',
    './public/**/*.js',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#5b53d6',
          700: '#4f46b8',
          800: '#3f3a93',
          900: '#312e75',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Arial', 'sans-serif'],
      },
    },
  },
  safelist: [
    // Status/badge colours built dynamically in some templates.
    { pattern: /(bg|text|border)-(green|red|yellow|gray|purple|brand|blue|slate)-(50|100|200|700|800|900)/ },
  ],
  plugins: [],
};
